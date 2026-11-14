#!/usr/bin/env python3
"""ShipSafe secrets gate (Gitleaks OSS CLI, pinned binary).

Runs `gitleaks dir` (working tree) or `gitleaks git` (full commit history)
with an explicit config and turns its JSON report into a pass/fail result.
The same script runs locally and in CI.

Exit codes (same contract as every ShipSafe gate):
  0  PASS  - scan completed and Gitleaks reported no findings
  1  FAIL  - at least one finding
  2  ERROR - scan incomplete or untrustworthy: config missing, gitleaks
             failed or wrote no/invalid report, scanned 0 bytes (or 0
             commits), git mode on a shallow clone (history incomplete), or a
             .gitleaksignore file is present. Fails closed.

Suppression policy: the only accepted suppression is the reviewed allowlist in
the config file. Inline `gitleaks:allow` comments are ignored
(--ignore-gitleaks-allow). Gitleaks 8.30.1 always reads a .gitleaksignore from
the scanned directory, even when --gitleaks-ignore-path points elsewhere, so
the gate refuses to run if one exists rather than let it hide findings.

Secret values are never printed: Gitleaks runs with --redact and this script
only prints rule id, file, line and commit.

Scope note: a PASS means "Gitleaks' rules matched nothing in what was
scanned". Secrets in unrecognised formats, low-entropy values, or outside the
scanned tree/history are not detected.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / ".gitleaks.toml"

ANSI = re.compile(r"\x1b\[[0-9;]*m")
BYTES_RE = re.compile(r"scanned ~(\d+) bytes")
COMMITS_RE = re.compile(r"(\d+) commits scanned")


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    commit: str = ""


@dataclass
class ScanResult:
    findings: list[Finding]
    problems: list[str]
    bytes_scanned: int | None = None
    commits_scanned: int | None = None

    @property
    def exit_code(self) -> int:
        if self.problems:
            return EXIT_ERROR
        return EXIT_FAIL if self.findings else EXIT_PASS


class ReportError(ValueError):
    """The Gitleaks report was missing or not in the expected shape."""


def parse_report(report: object) -> list[Finding]:
    """Decoded Gitleaks JSON report (a list of findings) -> Findings.
    Deliberately ignores the Secret/Match fields."""
    if not isinstance(report, list):
        raise ReportError("report is not a JSON list")
    findings = []
    for item in report:
        if not isinstance(item, dict) or "RuleID" not in item or "File" not in item:
            raise ReportError("malformed finding entry (missing RuleID/File)")
        findings.append(
            Finding(
                rule=str(item["RuleID"]),
                path=str(item["File"]),
                line=int(item.get("StartLine") or 0),
                commit=str(item.get("Commit") or "")[:12],
            )
        )
    findings.sort(key=lambda f: (f.path, f.line, f.rule, f.commit))
    return findings


def parse_log(log: str, mode: str) -> tuple[int | None, int | None, list[str]]:
    """Pull scan-volume numbers out of Gitleaks' log; flag empty scans."""
    log = ANSI.sub("", log)
    problems = []
    m = BYTES_RE.search(log)
    bytes_scanned = int(m.group(1)) if m else None
    if bytes_scanned is None:
        problems.append("could not confirm how much gitleaks scanned (no 'scanned ~N bytes' log line)")
    elif bytes_scanned == 0:
        problems.append("gitleaks scanned 0 bytes (empty or wrong target)")
    commits = None
    if mode == "git":
        m = COMMITS_RE.search(log)
        commits = int(m.group(1)) if m else None
        if not commits:
            problems.append("gitleaks scanned 0 commits (or did not report a commit count)")
    return bytes_scanned, commits, problems


def find_gitleaksignore(target: Path) -> list[str]:
    """Any .gitleaksignore under the target would silently suppress findings."""
    if target.is_file():
        return []
    hits = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        if ".gitleaksignore" in filenames:
            hits.append(str(Path(dirpath) / ".gitleaksignore"))
    return sorted(hits)


def is_shallow(target: Path) -> bool | None:
    """True/False for a git work tree; None if it is not one."""
    proc = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "--is-shallow-repository"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() == "true"


def preflight(target: Path, mode: str, config: Path) -> list[str]:
    problems = []
    if not config.is_file():
        problems.append(f"config not found: {config}")
    if not target.exists():
        problems.append(f"target not found: {target}")
        return problems
    for hit in find_gitleaksignore(target):
        problems.append(f"{hit} present: suppression must go through the reviewed config allowlist, not .gitleaksignore")
    if mode == "git":
        shallow = is_shallow(target)
        if shallow is None:
            problems.append(f"{target} is not a git work tree (git mode needs one)")
        elif shallow:
            problems.append("shallow clone: history is incomplete (CI must check out with fetch-depth: 0)")
    return problems


def run_gitleaks(gitleaks: str, mode: str, target: Path, config: Path, report_out: Path | None) -> tuple[object, str]:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gitleaks.json"
        cmd = [
            gitleaks, mode,
            "--config", str(config),     # explicit config; no auto-detection
            "--redact",                  # never put secret values in logs/report
            "--ignore-gitleaks-allow",   # inline suppression comments don't count
            "--exit-code", "0",          # findings are judged from the report
            "--report-format", "json",
            "--report-path", str(out),
            "--no-banner",
            "--log-level", "info",
            str(target),
        ]
        env = {k: v for k, v in os.environ.items() if k not in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")}
        env["NO_COLOR"] = "1"
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        log = proc.stdout + proc.stderr
        # With --exit-code 0, a non-zero exit means gitleaks itself failed.
        if proc.returncode != 0:
            raise ReportError(f"gitleaks exited {proc.returncode}: {ANSI.sub('', log).strip()[-1500:]}")
        if not out.exists():
            raise ReportError("gitleaks produced no report")
        text = out.read_text()
        if report_out:
            report_out.write_text(text)
        try:
            return json.loads(text), log
        except json.JSONDecodeError as exc:
            raise ReportError(f"gitleaks report is not valid JSON: {exc}") from exc


def scan(gitleaks: str, mode: str, target: Path, config: Path, report_out: Path | None = None) -> ScanResult:
    problems = preflight(target, mode, config)
    if problems:
        return ScanResult(findings=[], problems=problems)
    report, log = run_gitleaks(gitleaks, mode, target, config, report_out)
    findings = parse_report(report)
    bytes_scanned, commits, log_problems = parse_log(log, mode)
    return ScanResult(findings, log_problems, bytes_scanned, commits)


def render(result: ScanResult, label: str) -> str:
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}[result.exit_code]
    volume = []
    if result.commits_scanned is not None:
        volume.append(f"{result.commits_scanned} commit(s)")
    if result.bytes_scanned is not None:
        volume.append(f"~{result.bytes_scanned} bytes")
    lines = [f"secrets [{label}]: {verdict} - scanned {', '.join(volume) or 'nothing'}, "
             f"{len(result.findings)} finding(s) (values redacted)"]
    for f in result.findings:
        where = f" @ {f.commit}" if f.commit else ""
        lines.append(f"  - {f.path}:{f.line} {f.rule}{where}")
    for p in result.problems:
        lines.append(f"  - SCAN PROBLEM: {p}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", default=".", type=Path, help="directory (dir mode) or repo (git mode)")
    parser.add_argument("--mode", choices=["dir", "git"], default="dir",
                        help="dir: working tree files; git: every commit in history")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Gitleaks config (default: .gitleaks.toml)")
    parser.add_argument("--report", type=Path, help="also save the (redacted) Gitleaks JSON report here")
    parser.add_argument("--gitleaks", default="gitleaks", help="gitleaks executable")
    args = parser.parse_args(argv)

    label = f"{args.mode} {args.target}"
    try:
        result = scan(args.gitleaks, args.mode, args.target, args.config, args.report)
        text, code = render(result, label), result.exit_code
    except (ReportError, OSError, ValueError) as exc:
        text, code = f"secrets [{label}]: ERROR - {exc}", EXIT_ERROR
    print(text)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("### Secrets scan (Gitleaks)\n\n```\n" + text + "\n```\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
