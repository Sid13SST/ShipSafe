"""Offline unit tests for the dependency-audit gate logic (no network)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dependency_audit as da  # noqa: E402

CLEAN = {"dependencies": [{"name": "fastapi", "version": "1.0", "vulns": []}], "fixes": []}
VULN = {
    "dependencies": [
        {"name": "fastapi", "version": "1.0", "vulns": []},
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074"], "fix_versions": ["2.20.0"]},
                {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074"], "fix_versions": ["2.20.0"]},
            ],
        },
    ]
}
SKIPPED = {"dependencies": [{"name": "private-pkg", "skip_reason": "not found on PyPI"}]}


def test_clean_report_passes() -> None:
    r = da.parse_report(CLEAN)
    assert (r.exit_code, r.audited, r.findings) == (da.EXIT_PASS, 1, [])


def test_vulnerable_report_fails_and_dedupes() -> None:
    r = da.parse_report(VULN)
    assert r.exit_code == da.EXIT_FAIL
    assert [(f.package, f.vuln_id) for f in r.findings] == [("requests", "PYSEC-2018-28")]
    assert "FAIL" in da.render(r, "x") and "CVE-2018-18074" in da.render(r, "x")


def test_skipped_package_is_error_not_pass() -> None:
    r = da.parse_report(SKIPPED)
    assert r.exit_code == da.EXIT_ERROR
    assert "NOT AUDITED" in da.render(r, "x")


@pytest.mark.parametrize("bad", [None, [], {}, {"dependencies": "x"}, {"dependencies": [1]}])
def test_malformed_report_raises(bad: object) -> None:
    with pytest.raises(da.ReportError):
        da.parse_report(bad)


def _fake_pip_audit(tmp_path: Path, report: object | None, exit_code: int) -> str:
    """Create a stand-in pip-audit that writes `report` to --output."""
    body = "" if report is None else json.dumps(report)
    script = tmp_path / "fake-pip-audit"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "out = sys.argv[sys.argv.index('--output') + 1]\n"
        f"body = {body!r}\n"
        "if body:\n"
        "    open(out, 'w').write(body)\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.mark.parametrize(
    ("report", "tool_exit", "expected"),
    [(CLEAN, 0, da.EXIT_PASS), (VULN, 1, da.EXIT_FAIL), (None, 1, da.EXIT_ERROR), (SKIPPED, 0, da.EXIT_ERROR)],
)
def test_main_exit_codes(tmp_path: Path, report: object, tool_exit: int, expected: int) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==1.0\n")
    fake = _fake_pip_audit(tmp_path, report, tool_exit)
    assert da.main([str(req), "--pip-audit", fake]) == expected


def test_main_missing_file_is_error(tmp_path: Path) -> None:
    assert da.main([str(tmp_path / "nope.txt")]) == da.EXIT_ERROR


def test_worst_result_wins(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==1.0\n")
    clean = _fake_pip_audit(tmp_path, CLEAN, 0)
    assert da.main([str(req), str(tmp_path / "missing.txt"), "--pip-audit", clean]) == da.EXIT_ERROR


def test_writes_github_step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==1.0\n")
    da.main([str(req), "--pip-audit", _fake_pip_audit(tmp_path, CLEAN, 0)])
    assert "PASS" in summary.read_text()
