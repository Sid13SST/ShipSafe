"""Offline unit tests for the SAST gate logic (no semgrep, no network)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sast  # noqa: E402


def result(rule: str, severity: str, path: str = "app/main.py", line: int = 3) -> dict:
    return {
        "check_id": f"rules.semgrep.{rule}",
        "path": path,
        "start": {"line": line},
        "extra": {"severity": severity, "message": "msg"},
    }


def report(results=(), errors=(), scanned=("app/main.py",), skipped=()) -> dict:
    return {
        "results": list(results),
        "errors": list(errors),
        "paths": {"scanned": list(scanned)},
        "skipped_rules": list(skipped),
    }


def test_short_rule_id_strips_config_path_prefix() -> None:
    assert sast.short_rule_id("rules.semgrep.shipsafe.eval-exec-non-literal") == "shipsafe.eval-exec-non-literal"
    assert sast.short_rule_id("other.rule") == "other.rule"


def test_clean_report_passes() -> None:
    r = sast.parse_report(report())
    assert r.exit_code == sast.EXIT_PASS
    assert "PASS" in sast.render(r, "x")


@pytest.mark.parametrize("severity", ["ERROR", "WARNING", "CRITICAL", "HIGH", "MEDIUM", "SOMETHING-NEW"])
def test_failing_severities_fail(severity: str) -> None:
    r = sast.parse_report(report([result("shipsafe.x", severity)]))
    assert r.exit_code == sast.EXIT_FAIL


@pytest.mark.parametrize("severity", ["INFO", "LOW", "info"])
def test_informational_severities_pass(severity: str) -> None:
    r = sast.parse_report(report([result("shipsafe.weak-hash", severity)]))
    assert r.exit_code == sast.EXIT_PASS
    assert "informational, does not fail" in sast.render(r, "x")


def test_findings_rendered_with_location_and_rule() -> None:
    r = sast.parse_report(report([result("shipsafe.eval-exec-non-literal", "ERROR", "a.py", 7)]))
    assert "a.py:7 [ERROR] shipsafe.eval-exec-non-literal" in sast.render(r, "x")


def test_semgrep_errors_mean_error_even_with_findings() -> None:
    r = sast.parse_report(report([result("shipsafe.x", "ERROR")], errors=[{"message": "boom", "path": "b.py"}]))
    assert r.exit_code == sast.EXIT_ERROR
    assert "boom" in sast.render(r, "x")


def test_skipped_rules_mean_error() -> None:
    r = sast.parse_report(report(skipped=[{"rule_id": "rules.semgrep.shipsafe.y"}]))
    assert r.exit_code == sast.EXIT_ERROR
    assert "shipsafe.y" in r.problems[0]


def test_zero_files_scanned_is_error() -> None:
    assert sast.parse_report(report(scanned=())).exit_code == sast.EXIT_ERROR


@pytest.mark.parametrize("path", ["fixtures/sast/v.py", "./fixtures/v.py", "sub/fixtures/v.py"])
def test_forbidden_path_is_error(path: str) -> None:
    r = sast.parse_report(report(scanned=["app/main.py", path]), forbid_paths=["fixtures/"])
    assert r.exit_code == sast.EXIT_ERROR


def test_similar_but_allowed_path_is_not_forbidden() -> None:
    r = sast.parse_report(report(scanned=["fixtures_util.py"]), forbid_paths=["fixtures/"])
    assert r.exit_code == sast.EXIT_PASS


@pytest.mark.parametrize("bad", [None, [], {}, {"results": "x"}, {"results": []}, {"results": [1], "paths": {"scanned": ["a"]}}])
def test_malformed_report_raises(bad: object) -> None:
    with pytest.raises(sast.ReportError):
        sast.parse_report(bad)


def test_unparseable_python_detected(tmp_path: Path) -> None:
    good, bad, txt = tmp_path / "good.py", tmp_path / "bad.py", tmp_path / "notes.txt"
    good.write_text("x = 1\n")
    bad.write_text("def f(:\n    pass\n")
    txt.write_text("def f(:\n")
    problems = sast.unparseable_python([str(good), str(bad), str(txt)])
    assert len(problems) == 1 and "bad.py" in problems[0]


# --- main() with a stand-in semgrep executable -----------------------------

def fake_semgrep(tmp_path: Path, rep: object | None, exit_code: int = 0) -> str:
    """A stand-in semgrep that records its argv and writes `rep` to --output."""
    body = "" if rep is None else json.dumps(rep)
    script = tmp_path / "fake-semgrep"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(tmp_path / 'argv.json')!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        "out = sys.argv[sys.argv.index('--output') + 1]\n"
        f"body = {body!r}\n"
        "if body:\n"
        "    open(out, 'w').write(body)\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("x = 1\n")
    return src


@pytest.mark.parametrize(
    ("results", "tool_exit", "expected"),
    [
        ([], 0, sast.EXIT_PASS),
        ([result("shipsafe.x", "ERROR")], 0, sast.EXIT_FAIL),
        ([result("shipsafe.weak-hash", "INFO")], 0, sast.EXIT_PASS),
        ([], 2, sast.EXIT_ERROR),  # report written but semgrep itself failed
    ],
)
def test_main_exit_codes(tmp_path: Path, target: Path, results, tool_exit, expected) -> None:
    fake = fake_semgrep(tmp_path, report(results, scanned=[str(target / "main.py")]), tool_exit)
    assert sast.main([str(target), "--semgrep", fake]) == expected


def test_main_no_report_is_error(tmp_path: Path, target: Path) -> None:
    assert sast.main([str(target), "--semgrep", fake_semgrep(tmp_path, None, 7)]) == sast.EXIT_ERROR


def test_main_missing_rules_file_is_error(tmp_path: Path, target: Path) -> None:
    fake = fake_semgrep(tmp_path, report())
    assert sast.main([str(target), "--config", str(tmp_path / "nope.yml"), "--semgrep", fake]) == sast.EXIT_ERROR


def test_main_scanned_invalid_python_is_error(tmp_path: Path, target: Path) -> None:
    bad = target / "bad.py"
    bad.write_text("def f(:\n")
    fake = fake_semgrep(tmp_path, report(scanned=[str(bad)]))
    assert sast.main([str(target), "--semgrep", fake]) == sast.EXIT_ERROR


def test_main_passes_offline_flags_and_excludes(tmp_path: Path, target: Path) -> None:
    fake = fake_semgrep(tmp_path, report(scanned=[str(target / "main.py")]))
    saved = tmp_path / "raw.json"
    sast.main([str(target), "--exclude", "fixtures/", "--semgrep", fake, "--report", str(saved)])
    argv = json.loads((tmp_path / "argv.json").read_text())
    for flag in ["--metrics=off", "--disable-version-check", "--oss-only", "--json"]:
        assert flag in argv
    assert argv[argv.index("--exclude") + 1] == "fixtures/"
    assert argv[argv.index("--config") + 1].endswith("rules/semgrep/python-security.yml")
    assert argv[-1] == str(target)
    assert json.loads(saved.read_text())["paths"]["scanned"]


def test_main_writes_github_step_summary(tmp_path: Path, target: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    sast.main([str(target), "--semgrep", fake_semgrep(tmp_path, report(scanned=[str(target / "main.py")]))])
    assert "SAST" in summary.read_text() and "PASS" in summary.read_text()
