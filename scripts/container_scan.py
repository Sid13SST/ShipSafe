#!/usr/bin/env python3
"""ShipSafe container-scan gate (Trivy, pinned binary).

Two modes, same exit-code contract:

  image REF   `trivy image`: OS + language-package vulnerabilities in a built
              image, plus misconfiguration and secret checks on the image's
              config (history, USER, ENV, HEALTHCHECK).
  config DIR  `trivy config`: misconfiguration checks on Dockerfiles and other
              IaC files under DIR.

Gate policy:
  FAIL on  - a HIGH or CRITICAL vulnerability that has a fixed version
           - any misconfiguration with status FAIL (any severity)
           - any secret found in the image config
           - an image whose OS is past end of support (no more fixes coming)
  reported, does not fail
           - vulnerabilities with no fixed version yet, and LOW/MEDIUM ones

Exit codes (same contract as every ShipSafe gate):
  0  PASS  - scan completed and nothing matched the FAIL policy
  1  FAIL  - at least one finding matched the FAIL policy
  2  ERROR - scan incomplete or untrustworthy: trivy failed or wrote no /
             invalid report, report is for a different artifact, image OS not
             detected (OS packages not assessed), vulnerability DB older than
             --max-db-age-hours, config scan found no files, a forbidden path
             was scanned, or a scanned file carries an inline `trivy:ignore`.
             Fails closed.

Suppression: Trivy runs with `--config ""` and `--ignorefile ""` (so neither
trivy.yaml nor .trivyignore is loaded) and without any TRIVY_* environment
variables. Inline `trivy:ignore` comments cannot be switched off in Trivy, so
the gate refuses (ERROR) any scanned file that contains one.

TIME-VARIANCE: results depend on the vulnerability DB on the day of the scan.
A new advisory, or a new fix for an old one, can turn an unchanged image red.
A PASS means "no fixable HIGH/CRITICAL advisory in today's Trivy DB matched
the packages Trivy detected" - not that the image is free of vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

FAIL_VULN_SEVERITIES = {"HIGH", "CRITICAL"}
INLINE_IGNORE = re.compile(r"trivy:ignore", re.IGNORECASE)
MAX_LISTED = 40  # failing findings printed individually; the rest are counted


@dataclass
class Finding:
    kind: str       # vuln | misconfig | secret | eosl
    ident: str
    severity: str
    target: str
    detail: str


@dataclass
class ScanResult:
    label: str
    failing: list[Finding] = field(default_factory=list)
    info_counts: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    os_name: str = ""
    targets: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.problems:
            return EXIT_ERROR
        return EXIT_FAIL if self.failing else EXIT_PASS


class ScanError(ValueError):
    """Trivy could not be run or its output was unusable."""


# --- report evaluation (pure, unit-tested) ------------------------------------

def _under(path: str, prefix: str) -> bool:
    p = path[2:] if path.startswith("./") else path
    pre = prefix.rstrip("/")
    return p == pre or p.startswith(pre + "/")


def evaluate(report: object, mode: str, artifact: str, forbid: list[str] | None = None) -> ScanResult:
    if not isinstance(report, dict):
        raise ScanError("report is not a JSON object")
    if report.get("SchemaVersion") != 2:
        raise ScanError(f"unexpected report SchemaVersion {report.get('SchemaVersion')!r} (expected 2)")
    result = ScanResult(label=f"{mode} {artifact}")
    if mode == "image" and report.get("ArtifactName") != artifact:
        result.problems.append(f"report is for {report.get('ArtifactName')!r}, not {artifact!r}")

    results = report.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise ScanError("report 'Results' is not a list")

    if mode == "image":
        os_meta = (report.get("Metadata") or {}).get("OS")
        if not os_meta or not os_meta.get("Family"):
            result.problems.append("image OS not detected - OS packages were not assessed")
        else:
            result.os_name = f"{os_meta.get('Family')} {os_meta.get('Name', '')}".strip()
            if os_meta.get("EOSL"):
                result.failing.append(Finding("eosl", "EOSL", "HIGH", result.os_name,
                                              "OS is past end of support; no further security fixes"))
    elif not results:
        result.problems.append("trivy config found no files to check (wrong target or everything skipped)")

    info: dict[str, int] = {}
    for r in results:
        if not isinstance(r, dict) or "Target" not in r:
            raise ScanError("malformed result entry (missing Target)")
        target = str(r["Target"])
        result.targets.append(target)
        for fb in forbid or []:
            if _under(target, fb):
                result.problems.append(f"scanned {target}, which is under forbidden path {fb}")
        if mode == "image":
            target = target.replace(artifact, "<image>")  # keep output readable
        for v in r.get("Vulnerabilities") or []:
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            fixed = str(v.get("FixedVersion") or "")
            if sev in FAIL_VULN_SEVERITIES and fixed:
                result.failing.append(Finding(
                    "vuln", str(v.get("VulnerabilityID", "?")), sev, target,
                    f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '?')} -> fixed in {fixed}"))
            else:
                key = f"{sev} {'fixable' if fixed else 'no fix yet'}"
                info[key] = info.get(key, 0) + 1
        for m in r.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() == "FAIL":
                result.failing.append(Finding(
                    "misconfig", str(m.get("ID", "?")), str(m.get("Severity", "UNKNOWN")).upper(), target,
                    " ".join(str(m.get("Title", "")).split())))
        for s in r.get("Secrets") or []:
            # Never echo the matched value - rule and location only.
            result.failing.append(Finding(
                "secret", str(s.get("RuleID", "?")), str(s.get("Severity", "UNKNOWN")).upper(), target,
                f"{s.get('Title', 'secret')} (line {s.get('StartLine', '?')}, value not shown)"))
    result.info_counts = dict(sorted(info.items()))
    order = {"eosl": 0, "secret": 1, "misconfig": 2, "vuln": 3}
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    result.failing.sort(key=lambda f: (order.get(f.kind, 9), sev_rank.get(f.severity, 9), f.ident, f.target, f.detail))
    return result


def inline_ignores(base: Path, targets: list[str]) -> list[str]:
    """Scanned config files that contain a `trivy:ignore` comment."""
    hits = []
    for t in targets:
        p = base / t
        try:
            if p.is_file() and INLINE_IGNORE.search(p.read_text(encoding="utf-8", errors="replace")):
                hits.append(t)
        except OSError:
            continue
    return hits


def db_age_problem(version_json: object, max_age_hours: float, now: datetime | None = None) -> str | None:
    if not isinstance(version_json, dict):
        return "could not read trivy version/DB metadata"
    db = version_json.get("VulnerabilityDB") or {}
    stamp = db.get("UpdatedAt")
    if not stamp:
        return "vulnerability DB metadata missing (DB not downloaded?)"
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$", str(stamp))
    if not m:
        return f"unparseable DB timestamp {stamp!r}"
    updated = datetime.fromisoformat(m.group(1) + ((m.group(2) or "Z").replace("Z", "+00:00")))
    age_h = ((now or datetime.now(timezone.utc)) - updated).total_seconds() / 3600
    if age_h > max_age_hours:
        return f"vulnerability DB is {age_h:.0f}h old (limit {max_age_hours:.0f}h) - results would be stale"
    return None


def render(result: ScanResult) -> str:
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}[result.exit_code]
    kinds: dict[str, int] = {}
    for f in result.failing:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    head = f"container-scan [{result.label}]: {verdict}"
    if result.os_name:
        head += f" - OS {result.os_name}"
    head += f", {len(result.targets)} target(s); failing: " + (
        ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "none")
    lines = [head]
    if result.info_counts:
        lines.append("  informational (does not fail): " +
                     ", ".join(f"{n} {k}" for k, n in result.info_counts.items()))
    for f in result.failing[:MAX_LISTED]:
        lines.append(f"  - [{f.kind}] {f.ident} {f.severity} {f.detail} ({f.target})")
    if len(result.failing) > MAX_LISTED:
        lines.append(f"  ... and {len(result.failing) - MAX_LISTED} more failing finding(s)")
    for p in result.problems:
        lines.append(f"  - SCAN PROBLEM: {p}")
    return "\n".join(lines)


# --- running trivy --------------------------------------------------------------

def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")}


def _common(cache_dir: str | None) -> list[str]:
    flags = [
        "--config", "",            # never load trivy.yaml
        "--ignorefile", "",        # never load .trivyignore
        "--exit-code", "0",        # findings are judged from the report
        "--format", "json",
        "--disable-telemetry",
        "--skip-version-check",
    ]
    if cache_dir:
        flags += ["--cache-dir", cache_dir]
    return flags


def run_trivy(trivy: str, args: list[str], report_out: Path | None) -> object:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "trivy.json"
        proc = subprocess.run([trivy, *args, "--output", str(out)], capture_output=True, text=True, env=_env())
        if proc.returncode != 0:  # with --exit-code 0, non-zero means trivy itself failed
            tail = "\n".join(proc.stderr.strip().splitlines()[-6:])
            raise ScanError(f"trivy exited {proc.returncode}:\n{tail}")
        if not out.exists() or out.stat().st_size == 0:
            raise ScanError("trivy produced no report")
        text = out.read_text()
        if report_out:
            report_out.write_text(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScanError(f"trivy report is not valid JSON: {exc}") from exc


def trivy_version(trivy: str, cache_dir: str | None) -> object:
    cmd = [trivy, "version", "--format", "json"] + (["--cache-dir", cache_dir] if cache_dir else [])
    proc = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def scan_image(a: argparse.Namespace) -> ScanResult:
    args = ["image", *_common(a.cache_dir), "--no-progress",
            "--scanners", "vuln",
            "--image-config-scanners", "misconfig,secret",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--image-src", a.image_src]
    if a.platform:
        args += ["--platform", a.platform]
    report = run_trivy(a.trivy, [*args, a.target], a.report)
    result = evaluate(report, "image", a.target)
    problem = db_age_problem(trivy_version(a.trivy, a.cache_dir), a.max_db_age_hours)
    if problem:
        result.problems.append(problem)
    return result


def scan_config(a: argparse.Namespace) -> ScanResult:
    base = Path(a.target)
    if not base.is_dir():
        raise ScanError(f"config target is not a directory: {base}")
    args = ["config", *_common(a.cache_dir)]
    for d in a.skip_dir:
        args += ["--skip-dirs", d]
    report = run_trivy(a.trivy, [*args, str(base)], a.report)
    result = evaluate(report, "config", str(base), a.forbid_path)
    for hit in inline_ignores(base, result.targets):
        result.problems.append(f"{hit} contains an inline trivy:ignore comment; suppressions are not accepted")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["image", "config"])
    parser.add_argument("target", help="image reference (image mode) or directory (config mode)")
    parser.add_argument("--image-src", default="docker", choices=["docker", "remote", "containerd", "podman"],
                        help="image mode: where Trivy reads the image from (remote = registry, never run)")
    parser.add_argument("--platform", help="image mode: os/arch for multi-platform images")
    parser.add_argument("--skip-dir", action="append", default=[], help="config mode: directory to skip (repeatable)")
    parser.add_argument("--forbid-path", action="append", default=[], help="config mode: ERROR if a scanned file is under this path")
    parser.add_argument("--max-db-age-hours", type=float, default=72.0, help="image mode: max vulnerability DB age")
    parser.add_argument("--cache-dir", help="Trivy cache directory (DB location)")
    parser.add_argument("--report", type=Path, help="also save the raw Trivy JSON report here")
    parser.add_argument("--trivy", default="trivy", help="trivy executable")
    a = parser.parse_args(argv)

    try:
        result = scan_image(a) if a.mode == "image" else scan_config(a)
        text, code = render(result), result.exit_code
    except (ScanError, OSError) as exc:
        text, code = f"container-scan [{a.mode} {a.target}]: ERROR - {exc}", EXIT_ERROR
    print(text)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Container scan (Trivy, {a.mode})\n\n```\n{text}\n```\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
