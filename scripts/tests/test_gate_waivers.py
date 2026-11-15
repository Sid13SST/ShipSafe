"""Waivers applied end-to-end through each gate's main() (offline, fake tools)."""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_scan as cs  # noqa: E402
import dependency_audit as da  # noqa: E402
import dockerfile_lint as dl  # noqa: E402
import sast  # noqa: E402
from test_container_scan import IMG, fake_trivy, image_report, os_result, vuln  # noqa: E402
from test_dependency_audit import VULN, _fake_pip_audit  # noqa: E402
from test_dockerfile_lint import PINNED, fake_hadolint  # noqa: E402
from test_sast import fake_semgrep, report, result  # noqa: E402

REASON = "Accepted temporarily while the upstream fix is evaluated (issue 7)."
SOON = (date.today() + timedelta(days=30)).isoformat()
PAST = (date.today() - timedelta(days=1)).isoformat()


def waivers(tmp_path: Path, *entries: tuple[str, str, str, str | None]) -> str:
    text = "waivers:\n"
    for wid, gate, expires, scope in entries:
        text += f"  - id: {wid}\n    gate: {gate}\n    reason: \"{REASON}\"\n    expires: {expires}\n"
        if scope:
            text += f"    scope: {scope}\n"
    p = tmp_path / "waivers.yml"
    p.write_text(text)
    return str(p)


# --- dependency-audit ----------------------------------------------------------------

@pytest.fixture()
def req(tmp_path: Path) -> str:
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.19.1\n")
    return str(p)


def test_dep_audit_waiver_by_alias_passes(tmp_path: Path, req: str, capsys) -> None:
    w = waivers(tmp_path, ("CVE-2018-18074", "dependency-audit", SOON, "requests"))
    assert da.main([req, "--pip-audit", _fake_pip_audit(tmp_path, VULN, 1), "--waivers", w]) == da.EXIT_PASS
    assert "WAIVED: requests==2.19.1: PYSEC-2018-28" in capsys.readouterr().out


def test_dep_audit_scope_mismatch_still_fails(tmp_path: Path, req: str) -> None:
    w = waivers(tmp_path, ("PYSEC-2018-28", "dependency-audit", SOON, "urllib3"))
    assert da.main([req, "--pip-audit", _fake_pip_audit(tmp_path, VULN, 1), "--waivers", w]) == da.EXIT_FAIL


def test_dep_audit_expired_waiver_fails_even_without_findings(tmp_path: Path, req: str, capsys) -> None:
    from test_dependency_audit import CLEAN
    w = waivers(tmp_path, ("PYSEC-2018-28", "dependency-audit", PAST, None))
    assert da.main([req, "--pip-audit", _fake_pip_audit(tmp_path, CLEAN, 0), "--waivers", w]) == da.EXIT_FAIL
    assert "EXPIRED WAIVER" in capsys.readouterr().out


def test_dep_audit_invalid_waivers_is_error(tmp_path: Path, req: str) -> None:
    p = tmp_path / "bad.yml"
    p.write_text("waivers:\n  - id: X\n")
    assert da.main([req, "--pip-audit", _fake_pip_audit(tmp_path, VULN, 1), "--waivers", str(p)]) == da.EXIT_ERROR


def test_dep_audit_unused_waiver_reported(tmp_path: Path, req: str, capsys) -> None:
    from test_dependency_audit import CLEAN
    w = waivers(tmp_path, ("CVE-1999-0001", "dependency-audit", SOON, None))
    assert da.main([req, "--pip-audit", _fake_pip_audit(tmp_path, CLEAN, 0), "--waivers", w]) == da.EXIT_PASS
    assert "unused waiver" in capsys.readouterr().out


# --- sast ------------------------------------------------------------------------------

@pytest.fixture()
def src(tmp_path: Path) -> Path:
    d = tmp_path / "src"
    d.mkdir()
    (d / "main.py").write_text("x = 1\n")
    return d


def _sast(tmp_path: Path, src: Path, rule: str, w: str) -> int:
    rep = report([result(rule, "ERROR", str(src / "main.py"))], scanned=[str(src / "main.py")])
    return sast.main([str(src), "--semgrep", fake_semgrep(tmp_path, rep), "--waivers", w])


def test_sast_waiver_with_path_scope(tmp_path: Path, src: Path) -> None:
    w = waivers(tmp_path, ("shipsafe.eval-exec-non-literal", "sast", SOON, f"{src}/*.py"))
    assert _sast(tmp_path, src, "shipsafe.eval-exec-non-literal", w) == sast.EXIT_PASS


def test_sast_waiver_for_other_rule_does_not_apply(tmp_path: Path, src: Path) -> None:
    w = waivers(tmp_path, ("shipsafe.pickle-load", "sast", SOON, None))
    assert _sast(tmp_path, src, "shipsafe.eval-exec-non-literal", w) == sast.EXIT_FAIL


def test_sast_expired_and_problems_not_waivable(tmp_path: Path, src: Path) -> None:
    w = waivers(tmp_path, ("shipsafe.eval-exec-non-literal", "sast", PAST, None))
    assert _sast(tmp_path, src, "shipsafe.eval-exec-non-literal", w) == sast.EXIT_FAIL
    # a scan ERROR stays an ERROR even with a matching active waiver
    w2 = waivers(tmp_path, ("shipsafe.eval-exec-non-literal", "sast", SOON, None))
    rep = report([result("shipsafe.eval-exec-non-literal", "ERROR")], errors=[{"message": "boom"}],
                 scanned=[str(src / "main.py")])
    assert sast.main([str(src), "--semgrep", fake_semgrep(tmp_path, rep), "--waivers", w2]) == sast.EXIT_ERROR


# --- dockerfile-lint ----------------------------------------------------------------------

def test_dockerfile_policy_finding_waived(tmp_path: Path, capsys) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.13-slim\nUSER 10001\n")  # SS001 only
    w = waivers(tmp_path, ("SS001", "dockerfile-lint", SOON, str(df)))
    assert dl.main([str(df), "--hadolint", fake_hadolint(tmp_path, "[]"), "--waivers", w]) == dl.EXIT_PASS
    assert "WAIVED" in capsys.readouterr().out
    w2 = waivers(tmp_path, ("SS001", "dockerfile-lint", PAST, None))
    assert dl.main([str(df), "--hadolint", fake_hadolint(tmp_path, "[]"), "--waivers", w2]) == dl.EXIT_FAIL


def test_dockerfile_invalid_waivers_is_error(tmp_path: Path) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text(f"FROM {PINNED}\nUSER 10001\n")
    p = tmp_path / "w.yml"
    p.write_text("waivers:\n  - id: DL3008\n    gate: secrets\n    reason: \"" + REASON + "\"\n    expires: " + SOON + "\n")
    assert dl.main([str(df), "--hadolint", fake_hadolint(tmp_path, "[]"), "--waivers", str(p)]) == dl.EXIT_ERROR


# --- container-scan ----------------------------------------------------------------------------

def test_container_vuln_waived_by_package_scope(tmp_path: Path) -> None:
    rep = image_report([os_result([vuln("HIGH", "1.1", "CVE-2026-1", "zlib1g")])])
    ok = waivers(tmp_path, ("CVE-2026-1", "container-scan", SOON, "zlib1g"))
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, rep), "--waivers", ok]) == cs.EXIT_PASS
    other = waivers(tmp_path, ("CVE-2026-1", "container-scan", SOON, "openssl"))
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, rep), "--waivers", other]) == cs.EXIT_FAIL


def test_container_secret_and_eosl_not_waivable(tmp_path: Path) -> None:
    secret = {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "k", "StartLine": 1}
    rep = image_report([os_result(secrets=[secret])], os_meta={"Family": "debian", "Name": "10", "EOSL": True})
    w = waivers(tmp_path, ("aws-access-key-id", "container-scan", SOON, None), ("EOSL", "container-scan", SOON, None))
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, rep), "--waivers", w]) == cs.EXIT_FAIL


def test_container_expired_waiver_fails(tmp_path: Path) -> None:
    w = waivers(tmp_path, ("CVE-2026-1", "container-scan", PAST, None))
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, image_report()), "--waivers", w]) == cs.EXIT_FAIL


def test_default_waivers_path_is_cwd_relative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # the gate reads .shipsafe/waivers.yml of the repo being scanned (cwd), not of the tooling checkout
    (tmp_path / ".shipsafe").mkdir()
    (tmp_path / ".shipsafe" / "waivers.yml").write_text("not: valid\n")
    monkeypatch.chdir(tmp_path)
    assert cs.main(["image", IMG, "--trivy", fake_trivy(tmp_path, image_report())]) == cs.EXIT_ERROR
