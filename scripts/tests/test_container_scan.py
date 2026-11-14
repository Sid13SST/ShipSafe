"""Offline unit tests for the container-scan gate (no trivy, no docker, no network)."""

from __future__ import annotations

import json
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import container_scan as cs  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
IMG = "shipsafe-demo:ci"


def vuln(sev: str, fixed: str = "", vid: str = "CVE-1", pkg: str = "zlib1g") -> dict:
    v = {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": "1.0", "Severity": sev}
    if fixed:
        v["FixedVersion"] = fixed
    return v


def image_report(results=(), os_meta=None, artifact=IMG) -> dict:
    return {"SchemaVersion": 2, "ArtifactName": artifact,
            "Metadata": {"OS": {"Family": "debian", "Name": "13.7"} if os_meta is None else os_meta},
            "Results": list(results)}


def os_result(vulns=(), misconf=(), secrets=()) -> dict:
    return {"Target": f"{IMG} (debian 13.7)", "Class": "os-pkgs",
            "Vulnerabilities": list(vulns), "Misconfigurations": list(misconf), "Secrets": list(secrets)}


# --- installer pin ----------------------------------------------------------------

def test_installer_pins_version_and_all_checksums() -> None:
    text = (REPO / "scripts" / "install_trivy.sh").read_text()
    m = re.search(r'^TRIVY_VERSION="(\d+)\.(\d+)\.(\d+)"$', text, re.M)
    assert m
    major, minor, patch = map(int, m.groups())
    # never the compromised 0.69.4 binary (CVE-2026-33634); stay past the incident
    assert (major, minor) > (0, 69)
    assert len(re.findall(r'(Linux|macOS)-(64bit|ARM64)\)\s+echo "([0-9a-f]{64})"', text)) == 4


def test_no_trivy_actions_or_images_in_workflows() -> None:
    for wf in (REPO / ".github" / "workflows").glob("*.yml"):
        text = wf.read_text()
        assert "aquasecurity/trivy-action" not in text and "aquasecurity/setup-trivy" not in text, wf
        assert not re.search(r"image:\s*\S*trivy", text), wf


# --- vulnerability policy -----------------------------------------------------------

@pytest.mark.parametrize(("sev", "fixed", "fails"), [
    ("CRITICAL", "1.1", True), ("HIGH", "1.1", True),
    ("CRITICAL", "", False), ("HIGH", "", False),
    ("MEDIUM", "1.1", False), ("LOW", "1.1", False), ("UNKNOWN", "1.1", False),
])
def test_vuln_policy(sev: str, fixed: str, fails: bool) -> None:
    r = cs.evaluate(image_report([os_result([vuln(sev, fixed)])]), "image", IMG)
    assert (r.exit_code == cs.EXIT_FAIL) is fails
    if not fails:
        assert r.exit_code == cs.EXIT_PASS and sum(r.info_counts.values()) == 1


def test_unfixed_counted_as_informational() -> None:
    r = cs.evaluate(image_report([os_result([vuln("HIGH"), vuln("HIGH"), vuln("MEDIUM", "2")])]), "image", IMG)
    assert r.info_counts == {"HIGH no fix yet": 2, "MEDIUM fixable": 1}
    assert "informational (does not fail): 2 HIGH no fix yet, 1 MEDIUM fixable" in cs.render(r)


# --- misconfig / secrets / EOSL -------------------------------------------------------

@pytest.mark.parametrize("sev", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_any_failed_misconfig_fails(sev: str) -> None:
    m = {"ID": "DS-0002", "Severity": sev, "Status": "FAIL", "Title": "Image user should not be 'root'"}
    r = cs.evaluate(image_report([os_result(misconf=[m])]), "image", IMG)
    assert r.exit_code == cs.EXIT_FAIL
    assert "[misconfig] DS-0002" in cs.render(r)


def test_passed_misconfig_ignored() -> None:
    m = {"ID": "DS-0002", "Severity": "HIGH", "Status": "PASS"}
    assert cs.evaluate(image_report([os_result(misconf=[m])]), "image", IMG).exit_code == cs.EXIT_PASS


def test_secret_fails_and_value_never_rendered() -> None:
    s = {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS key", "StartLine": 3,
         "Match": "ENV KEY=placeholder-secret-value"}
    out = cs.render(cs.evaluate(image_report([os_result(secrets=[s])]), "image", IMG))
    assert "[secret] aws-access-key-id" in out and "placeholder-secret-value" not in out


def test_eosl_os_fails() -> None:
    r = cs.evaluate(image_report(os_meta={"Family": "debian", "Name": "10.13", "EOSL": True}), "image", IMG)
    assert r.exit_code == cs.EXIT_FAIL and r.failing[0].kind == "eosl"


# --- fail-closed --------------------------------------------------------------------------

@pytest.mark.parametrize("os_meta", [{}, {"Name": "x"}])
def test_os_not_detected_is_error(os_meta: dict) -> None:
    assert cs.evaluate(image_report(os_meta=os_meta), "image", IMG).exit_code == cs.EXIT_ERROR


def test_wrong_artifact_is_error() -> None:
    assert cs.evaluate(image_report(artifact="other:1"), "image", IMG).exit_code == cs.EXIT_ERROR


@pytest.mark.parametrize("bad", [None, [], {"SchemaVersion": 1}, {"SchemaVersion": 2, "Results": "x"},
                                 {"SchemaVersion": 2, "Results": [{"Class": "x"}]}])
def test_malformed_report_raises(bad: object) -> None:
    with pytest.raises(cs.ScanError):
        cs.evaluate(bad, "config", ".")


def test_config_with_no_files_is_error() -> None:
    assert cs.evaluate({"SchemaVersion": 2}, "config", ".").exit_code == cs.EXIT_ERROR


@pytest.mark.parametrize(("target", "forbidden"), [
    ("fixtures/container-scan/Dockerfile.misconfig", True), ("./fixtures/x/Dockerfile", True),
    ("demo-app/Dockerfile", False), ("fixtures_notes/Dockerfile", False),
])
def test_forbidden_config_target(target: str, forbidden: bool) -> None:
    rep = {"SchemaVersion": 2, "Results": [{"Target": target, "Misconfigurations": []}]}
    r = cs.evaluate(rep, "config", ".", ["fixtures/"])
    assert (r.exit_code == cs.EXIT_ERROR) is forbidden


def test_inline_ignore_detection(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Dockerfile").write_text("# trivy:ignore:DS-0001\nFROM x:latest\n")
    (tmp_path / "Dockerfile").write_text("FROM x@sha256:abc\n")
    assert cs.inline_ignores(tmp_path, ["a/Dockerfile", "Dockerfile", "missing"]) == ["a/Dockerfile"]


# --- DB freshness ---------------------------------------------------------------------------

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(("stamp", "ok"), [
    ("2026-11-14T05:05:54.014761714Z", True),
    ((NOW - timedelta(hours=71)).strftime("%Y-%m-%dT%H:%M:%SZ"), True),
    ((NOW - timedelta(hours=73)).strftime("%Y-%m-%dT%H:%M:%S.123Z"), False),
    ("2026-11-01T00:00:00+00:00", False),
])
def test_db_age(stamp: str, ok: bool) -> None:
    problem = cs.db_age_problem({"VulnerabilityDB": {"UpdatedAt": stamp}}, 72, now=NOW)
    assert (problem is None) is ok


@pytest.mark.parametrize("bad", [None, {}, {"VulnerabilityDB": {}}, {"VulnerabilityDB": {"UpdatedAt": "yesterday"}}])
def test_db_metadata_missing_is_problem(bad: object) -> None:
    assert cs.db_age_problem(bad, 72, now=NOW)


# --- main() with a stand-in trivy ---------------------------------------------------------------

def fake_trivy(tmp_path: Path, report: object | None, exit_code: int = 0, db_age_h: float = 1) -> str:
    stamp = (datetime.now(timezone.utc) - timedelta(hours=db_age_h)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    body = "" if report is None else json.dumps(report)
    script = tmp_path / "fake-trivy"
    script.write_text(
        "#!/usr/bin/env python3\nimport json, os, sys\n"
        "if sys.argv[1] == 'version':\n"
        f"    print(json.dumps({{'Version': '0.76.2', 'VulnerabilityDB': {{'UpdatedAt': {stamp!r}}}}})); sys.exit(0)\n"
        f"open({str(tmp_path / 'call.json')!r}, 'w').write(json.dumps("
        "{'argv': sys.argv[1:], 'env': sorted(k for k in os.environ if k.startswith('TRIVY_'))}))\n"
        "out = sys.argv[sys.argv.index('--output') + 1]\n"
        f"body = {body!r}\n"
        "if body:\n    open(out, 'w').write(body)\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.mark.parametrize(("report", "tool_exit", "age", "expected"), [
    (image_report([os_result([vuln("HIGH")])]), 0, 1, cs.EXIT_PASS),
    (image_report([os_result([vuln("CRITICAL", "2")])]), 0, 1, cs.EXIT_FAIL),
    (image_report(), 0, 200, cs.EXIT_ERROR),     # stale DB
    (image_report(), 1, 1, cs.EXIT_ERROR),       # trivy failed
    (None, 0, 1, cs.EXIT_ERROR),                 # no report
])
def test_main_image_exit_codes(tmp_path: Path, report, tool_exit, age, expected) -> None:
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, report, tool_exit, age)]) == expected


def test_main_image_flags_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL")
    monkeypatch.setenv("TRIVY_IGNOREFILE", "/elsewhere")
    cs.main(["image", IMG, "--image-src", "remote", "--platform", "linux/amd64",
             "--trivy", fake_trivy(tmp_path, image_report())])
    call = json.loads((tmp_path / "call.json").read_text())
    argv = call["argv"]
    assert argv[0] == "image" and argv[-3] == IMG
    assert argv[argv.index("--config") + 1] == "" and argv[argv.index("--ignorefile") + 1] == ""
    assert argv[argv.index("--exit-code") + 1] == "0"
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert argv[argv.index("--image-config-scanners") + 1] == "misconfig,secret"
    assert argv[argv.index("--image-src") + 1] == "remote"
    assert "--ignore-unfixed" not in argv  # unfixed must be visible (reported, not failing)
    assert call["env"] == [], "TRIVY_* env must not reach trivy"


def test_main_config_inline_ignore_is_error(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("# trivy:ignore:DS-0002\nFROM x\n")
    rep = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": []}]}
    assert cs.main(["config", str(proj), "--trivy", fake_trivy(tmp_path, rep)]) == cs.EXIT_ERROR


def test_main_config_passes_skip_dirs(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM x\n")
    rep = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": []}]}
    assert cs.main(["config", str(proj), "--skip-dir", "fixtures", "--trivy", fake_trivy(tmp_path, rep)]) == cs.EXIT_PASS
    argv = json.loads((tmp_path / "call.json").read_text())["argv"]
    assert argv[argv.index("--skip-dirs") + 1] == "fixtures" and "--no-progress" not in argv


def test_main_config_missing_dir_is_error(tmp_path: Path) -> None:
    assert cs.main(["config", str(tmp_path / "nope"), "--trivy", fake_trivy(tmp_path, {})]) == cs.EXIT_ERROR


def test_main_writes_github_step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, image_report())])
    assert "Container scan" in summary.read_text() and "PASS" in summary.read_text()
