#!/usr/bin/env python3
"""ShipSafe SAST gate (Semgrep OSS, vendored rules, offline).

Runs `semgrep scan` with the repository's vendored rules and turns its JSON
report into a pass/fail gate result. The same script runs locally and in CI.

Exit codes (same contract as every ShipSafe gate):
  0  PASS  - scan completed; no ERROR/WARNING-severity findings
  1  FAIL  - at least one finding at a failing severity
  2  ERROR - scan incomplete or untrustworthy: semgrep failed or reported
             errors, skipped rules, scanned zero files, scanned a path that
             must be excluded, or a scanned .py file is not valid Python.
             Fails closed.

Why the extra Python parse check: Semgrep's parser is error-tolerant and, as
of 1.185.0, reports no error for files it cannot parse - they count as
scanned with no findings. The gate therefore re-parses every scanned .py
file with Python's own `ast` and treats a failure as ERROR.

Scope note: a PASS means "these vendored patterns did not match the scanned
files". It is not evidence that the code is free of vulnerabilities.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

# Semgrep's classic severities plus the newer names, so a rule written either
# way is classified. Anything not listed here is treated as failing.
FAILING_SEVERITIES = {"ERROR", "WARNING", "CRITICAL", "HIGH", "MEDIUM"}
NON_FAILING_SEVERITIES = {"INFO", "LOW"}

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "rules" / "semgrep" / "python-security.yml"


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str

    @property
    def failing(self) -> bool:
        return self.severity not in NON_FAILING_SEVERITIES


@dataclass
class ScanResult:
    scanned: list[str]
    findings: list[Finding]
    problems: list[str]  # reasons the scan cannot be trusted

    @property
    def failing(self) -> list[Finding]:
        return [f for f in self.findings if f.failing]

    @property
    def exit_code(self) -> int:
        if self.problems:
            return EXIT_ERROR
        return EXIT_FAIL if self.failing else EXIT_PASS


class ReportError(ValueError):
    """The Semgrep report was missing or not in the expected shape."""


def short_rule_id(check_id: str) -> str:
    """Semgrep prefixes local rule ids with the config's directory path
    (e.g. 'rules.semgrep.shipsafe.eval-exec-non-literal'); keep the rule's own id."""
    marker = "shipsafe."
    idx = check_id.find(marker)
    return check_id[idx:] if idx >= 0 else check_id


def parse_report(report: object, forbid_paths: list[str] | None = None) -> ScanResult:
    """Convert a decoded Semgrep JSON report into a ScanResult."""
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ReportError("report has no 'results' list")
    problems: list[str] = []

    for err in report.get("errors", []) or []:
        if isinstance(err, dict):
            where = err.get("path") or ""
            msg = err.get("message") or err.get("type") or "unknown error"
            problems.append(f"semgrep error{f' in {where}' if where else ''}: {str(msg).strip()[:300]}")
        else:
            problems.append(f"semgrep error: {err!r}")

    skipped_rules = report.get("skipped_rules") or []
    if skipped_rules:
        ids = [short_rule_id(str(r.get("rule_id", r))) if isinstance(r, dict) else str(r) for r in skipped_rules]
        problems.append(f"rules skipped by semgrep (not run): {', '.join(ids)}")

    paths = report.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    if not isinstance(scanned, list):
        raise ReportError("report has no 'paths.scanned' list")
    scanned = [str(p) for p in scanned]
    if not scanned:
        problems.append("semgrep scanned 0 files (wrong target or everything excluded)")
    for forbidden in forbid_paths or []:
        prefix = forbidden.rstrip("/") + "/"
        hits = [p for p in scanned if p == forbidden.rstrip("/") or p.startswith(prefix) or f"/{prefix}" in p]
        if hits:
            problems.append(f"scanned paths under forbidden '{forbidden}': {', '.join(hits)}")

    findings: list[Finding] = []
    for r in report["results"]:
        if not isinstance(r, dict) or "check_id" not in r:
            raise ReportError(f"malformed result entry: {r!r}")
        extra = r.get("extra") or {}
        findings.append(
            Finding(
                rule=short_rule_id(str(r["check_id"])),
                severity=str(extra.get("severity", "UNKNOWN")).upper(),
                path=str(r.get("path", "?")),
                line=int((r.get("start") or {}).get("line", 0)),
                message=" ".join(str(extra.get("message", "")).split()),
            )
        )
    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    return ScanResult(scanned=scanned, findings=findings, problems=problems)


def unparseable_python(paths: list[str]) -> list[str]:
    """Return a problem string for each .py file Python itself cannot parse."""
    problems = []
    for p in paths:
        if not p.endswith(".py"):
            continue
        try:
            ast.parse(Path(p).read_bytes(), filename=p)
        except (SyntaxError, ValueError, OSError) as exc:
            problems.append(f"{p} is not valid Python for this interpreter ({type(exc).__name__}: {exc}); "
                            "semgrep may not have analysed it")
    return problems


def render(result: ScanResult, label: str) -> str:
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}[result.exit_code]
    lines = [
        f"sast [{label}]: {verdict} - {len(result.scanned)} file(s) scanned, "
        f"{len(result.failing)} failing finding(s), "
        f"{len(result.findings) - len(result.failing)} informational"
    ]
    for f in result.findings:
        tag = "" if f.failing else " (informational, does not fail)"
        lines.append(f"  - {f.path}:{f.line} [{f.severity}] {f.rule}{tag}")
    for p in result.problems:
        lines.append(f"  - SCAN PROBLEM: {p}")
    return "\n".join(lines)


def run_semgrep(semgrep: str, config: Path, targets: list[str], excludes: list[str], report_out: Path | None) -> object:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "semgrep.json"
        cmd = [
            semgrep, "scan",
            "--config", str(config),   # local vendored rules only - no registry
            "--json", "--output", str(out),
            "--metrics=off",           # no telemetry
            "--disable-version-check",  # no network call to check for updates
            "--oss-only",              # open-source engine only
            "--quiet",
        ]
        for ex in excludes:
            cmd += ["--exclude", ex]
        cmd += targets
        env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if not out.exists() or out.stat().st_size == 0:
            raise ReportError(f"semgrep produced no report (exit {proc.returncode}):\n{proc.stderr.strip()[-2000:]}")
        text = out.read_text()
        if report_out:
            report_out.write_text(text)
        try:
            report = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ReportError(f"semgrep report is not valid JSON: {exc}") from exc
        # Without --error, semgrep exits 0 whether or not it found anything;
        # any other exit code means the scan itself went wrong.
        if proc.returncode != 0:
            raise ReportError(f"semgrep exited {proc.returncode}:\n{proc.stderr.strip()[-2000:]}")
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("targets", nargs="+", help="files/directories to scan")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="vendored Semgrep rules file")
    parser.add_argument("--exclude", action="append", default=[], help="path pattern to exclude (repeatable)")
    parser.add_argument("--forbid-path", action="append", default=[],
                        help="fail with ERROR if any scanned file is under this path (repeatable)")
    parser.add_argument("--report", type=Path, help="also save the raw Semgrep JSON report here")
    parser.add_argument("--semgrep", default="semgrep", help="semgrep executable")
    args = parser.parse_args(argv)

    label = " ".join(args.targets)
    if not args.config.is_file():
        text, code = f"sast [{label}]: ERROR - rules file not found: {args.config}", EXIT_ERROR
    else:
        try:
            report = run_semgrep(args.semgrep, args.config, args.targets, args.exclude, args.report)
            result = parse_report(report, args.forbid_path)
            result.problems += unparseable_python(result.scanned)
            text, code = render(result, label), result.exit_code
        except (ReportError, OSError, ValueError) as exc:
            text, code = f"sast [{label}]: ERROR - {exc}", EXIT_ERROR
    print(text)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("### SAST (Semgrep, vendored rules)\n\n```\n" + text + "\n```\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
