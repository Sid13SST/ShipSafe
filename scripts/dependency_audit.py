#!/usr/bin/env python3
"""ShipSafe dependency-audit gate.

Runs pip-audit against one or more fully pinned requirements files and turns
its JSON report into a pass/fail gate result. The same script is used locally
and in CI so both produce the same verdict.

Exit codes (stable; CI and the self-test rely on them):
  0  PASS  - every listed package was audited and no known advisories matched
  1  FAIL  - at least one package has a known advisory
  2  ERROR - the audit could not be completed (tool error, unpinned or
             unauditable package, unreadable report). Fails closed: an audit
             that did not run is never reported as a pass.

Waivers: findings can be waived for a limited time in .shipsafe/waivers.yml
(gate: dependency-audit; id matches the advisory id or any alias; optional
scope = package name). An expired waiver FAILS the run; an invalid waivers
file is an ERROR. See scripts/waivers.py.

Scope note: a PASS means "no advisory in the PyPI/OSV data pip-audit queried
matched these exact pins at the time of the run". It is not a guarantee that
the dependencies are free of vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import waivers as wv

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2


@dataclass
class Finding:
    package: str
    version: str
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    fix_versions: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    audited: int
    findings: list[Finding]
    skipped: list[tuple[str, str]]  # (package, reason)
    waived: list[tuple[Finding, wv.Waiver]] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.skipped:
            return EXIT_ERROR
        return EXIT_FAIL if self.findings else EXIT_PASS


class ReportError(ValueError):
    """The pip-audit report was missing or not in the expected shape."""


def parse_report(report: object) -> AuditResult:
    """Convert a pip-audit JSON report (already decoded) into an AuditResult."""
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise ReportError("report has no 'dependencies' list")
    findings: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    audited = 0
    seen: set[tuple[str, str, str]] = set()
    for dep in report["dependencies"]:
        if not isinstance(dep, dict) or "name" not in dep:
            raise ReportError(f"malformed dependency entry: {dep!r}")
        name = str(dep["name"])
        if "skip_reason" in dep:
            skipped.append((name, str(dep["skip_reason"])))
            continue
        audited += 1
        for vuln in dep.get("vulns", []):
            key = (name, str(dep.get("version", "?")), str(vuln.get("id", "?")))
            if key in seen:  # pip-audit can report the same advisory twice
                continue
            seen.add(key)
            findings.append(
                Finding(
                    package=name,
                    version=str(dep.get("version", "?")),
                    vuln_id=str(vuln.get("id", "?")),
                    aliases=[str(a) for a in vuln.get("aliases", [])],
                    fix_versions=[str(v) for v in vuln.get("fix_versions", [])],
                )
            )
    return AuditResult(audited=audited, findings=findings, skipped=skipped)


def render(result: AuditResult, label: str) -> str:
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}[result.exit_code]
    lines = [
        f"dependency-audit [{label}]: {verdict} - "
        f"{result.audited} package(s) audited, {len(result.findings)} known advisory match(es), "
        f"{len(result.skipped)} skipped"
    ]
    for f in result.findings:
        alias = f" ({', '.join(f.aliases)})" if f.aliases else ""
        fix = ", ".join(f.fix_versions) if f.fix_versions else "none listed"
        lines.append(f"  - {f.package}=={f.version}: {f.vuln_id}{alias}; fixed in: {fix}")
    for f, w in result.waived:
        lines.append(f"  - WAIVED: {f.package}=={f.version}: {f.vuln_id} until {w.expires.isoformat()} ({w.reason})")
    for name, reason in result.skipped:
        lines.append(f"  - {name}: NOT AUDITED ({reason})")
    return "\n".join(lines)


def apply_waivers(result: AuditResult, ws: wv.WaiverSet) -> set[wv.Waiver]:
    """Move waived findings out of result.findings; return the waivers used."""
    remaining, waived, _ = wv.apply(ws, result.findings,
                                    key=lambda f: ([f.vuln_id, *f.aliases], [f.package]))
    result.findings, result.waived = remaining, waived
    return {w for _, w in waived}


def run_pip_audit(requirements: Path, pip_audit: str) -> object:
    """Run pip-audit on a pinned requirements file without installing anything."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        cmd = [
            pip_audit,
            "--requirement", str(requirements),
            "--no-deps",          # file must already be fully pinned (lockfile)
            "--disable-pip",      # never create a venv / install the packages
            "--format", "json",
            "--output", str(out),
            "--progress-spinner", "off",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # pip-audit exits 1 both for "vulns found" and for errors, so the
        # report itself is the source of truth. No report => error.
        if not out.exists() or out.stat().st_size == 0:
            raise ReportError(
                f"pip-audit produced no report (exit {proc.returncode}):\n{proc.stderr.strip()}"
            )
        try:
            return json.loads(out.read_text())
        except json.JSONDecodeError as exc:
            raise ReportError(f"pip-audit report is not valid JSON: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("requirements", nargs="+", type=Path, help="pinned requirements file(s)")
    parser.add_argument("--pip-audit", default="pip-audit", help="pip-audit executable")
    parser.add_argument("--waivers", type=Path, default=wv.DEFAULT_PATH,
                        help="waivers file (default: .shipsafe/waivers.yml; missing = no waivers)")
    args = parser.parse_args(argv)

    worst = EXIT_PASS
    summary: list[str] = []
    try:
        ws = wv.load(args.waivers, "dependency-audit")
    except wv.WaiverFileError as exc:
        text = f"dependency-audit: ERROR - invalid waivers file: {exc}"
        print(text)
        _write_summary([text])
        return EXIT_ERROR
    used: set[wv.Waiver] = set()
    for req in args.requirements:
        if not req.is_file():
            text = f"dependency-audit [{req}]: ERROR - file not found"
            code = EXIT_ERROR
        else:
            try:
                result = parse_report(run_pip_audit(req, args.pip_audit))
                used |= apply_waivers(result, ws)
                text, code = render(result, str(req)), result.exit_code
            except (ReportError, OSError) as exc:
                text, code = f"dependency-audit [{req}]: ERROR - {exc}", EXIT_ERROR
        print(text)
        summary.append(text)
        worst = max(worst, code)

    tail = wv.render_lines([], [w for w in ws.active if w not in used], ws.expired_messages())
    if tail:
        print("dependency-audit waivers:\n" + "\n".join(tail))
        summary.append("\n".join(tail))
    if ws.expired:
        worst = max(worst, EXIT_FAIL)
    _write_summary(summary)
    return worst


def _write_summary(summary: list[str]) -> None:
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("### Dependency audit (pip-audit)\n\n```\n" + "\n".join(summary) + "\n```\n")


if __name__ == "__main__":
    sys.exit(main())
