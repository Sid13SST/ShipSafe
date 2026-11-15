"""Offline unit tests for the secrets gate (no gitleaks binary, no network).

Note: no string in this file may match a Gitleaks rule - the project secrets
scan covers this file too. Fake reports below use placeholder values only.
"""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import secrets_scan as ss  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PLACEHOLDER = "placeholder-value-for-tests"


def finding(rule="github-pat", path="app/x.env", line=3, commit="") -> dict:
    return {"RuleID": rule, "File": path, "StartLine": line, "Commit": commit,
            "Secret": PLACEHOLDER, "Match": f"TOKEN={PLACEHOLDER}"}


# --- project allowlist review ----------------------------------------------

def test_project_config_allowlists_only_fixtures_path() -> None:
    cfg = tomllib.loads((REPO / ".gitleaks.toml").read_text())
    assert cfg["extend"] == {"useDefault": True}, "must extend the default rules and nothing else"
    assert "rules" not in cfg, "project config must not add or override rules"
    assert "allowlist" not in cfg, "use [[allowlists]] only"
    allowlists = cfg["allowlists"]
    assert len(allowlists) == 1
    (al,) = allowlists
    assert set(al) <= {"description", "paths"}, f"unexpected allowlist keys: {set(al)}"
    assert al["paths"] == [r"^(\./)?fixtures/"]


@pytest.mark.parametrize(
    ("path", "allowed"),
    [("fixtures/secrets/a.env", True), ("./fixtures/x", True),
     ("demo-app/fixtures/x", False), ("scripts/fixtures.py", False), ("demo-app/app/main.py", False)],
)
def test_project_allowlist_regex_is_anchored(path: str, allowed: bool) -> None:
    (pattern,) = tomllib.loads((REPO / ".gitleaks.toml").read_text())["allowlists"][0]["paths"]
    assert bool(re.search(pattern, path)) is allowed


def test_default_only_config_has_no_allowlist() -> None:
    cfg = tomllib.loads((REPO / "rules" / "gitleaks" / "default-only.toml").read_text())
    assert cfg["extend"] == {"useDefault": True}
    assert not {"allowlist", "allowlists", "rules"} & set(cfg)


def test_installer_pins_version_and_all_checksums() -> None:
    text = (REPO / "scripts" / "install_gitleaks.sh").read_text()
    assert re.search(r'^GITLEAKS_VERSION="\d+\.\d+\.\d+"$', text, re.M)
    hashes = re.findall(r'(linux|darwin)_(x64|arm64)\)\s+echo "([0-9a-f]{64})"', text)
    assert len(hashes) == 4


# --- report / log parsing ---------------------------------------------------

def test_parse_report_and_never_render_secret() -> None:
    findings = ss.parse_report([finding(commit="0123456789abcdef0123")])
    assert findings[0].commit == "0123456789ab"
    out = ss.render(ss.ScanResult(findings, [], 10, 1), "x")
    assert "app/x.env:3 github-pat @ 0123456789ab" in out
    assert PLACEHOLDER not in out


@pytest.mark.parametrize("bad", [None, {}, "x", [1], [{"RuleID": "r"}], [{"File": "f"}]])
def test_malformed_report_raises(bad: object) -> None:
    with pytest.raises(ss.ReportError):
        ss.parse_report(bad)


def test_parse_log_dir_mode_reads_bytes_and_strips_ansi() -> None:
    log = "\x1b[90m11:47AM\x1b[0m INF \x1b[1mscanned ~431 bytes (431 bytes) in 17ms\x1b[0m\n"
    assert ss.parse_log(log, "dir") == (431, None, [])


def test_parse_log_git_mode_reads_commits() -> None:
    log = "INF 7 commits scanned.\nINF scanned ~81606 bytes (81.61 KB) in 210ms\n"
    assert ss.parse_log(log, "git") == (81606, 7, [])


@pytest.mark.parametrize(
    ("log", "mode"),
    [("INF scanned ~0 bytes (0) in 1ms", "dir"), ("INF no leaks found", "dir"),
     ("INF 0 commits scanned.\nINF scanned ~5 bytes", "git"), ("INF scanned ~5 bytes", "git")],
)
def test_parse_log_empty_or_unknown_scan_is_problem(log: str, mode: str) -> None:
    assert ss.parse_log(log, mode)[2]


# --- preflight ---------------------------------------------------------------

def test_gitleaksignore_anywhere_is_error(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".gitleaksignore").write_text("x:y:1\n")
    problems = ss.preflight(tmp_path, "dir", REPO / ".gitleaks.toml")
    assert any(".gitleaksignore" in p for p in problems)


def test_missing_config_and_target_are_errors(tmp_path: Path) -> None:
    problems = ss.preflight(tmp_path / "nope", "dir", tmp_path / "nope.toml")
    assert len(problems) == 2


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_git_mode_rejects_shallow_and_non_git(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git("init", "-q", cwd=origin)
    for i in range(2):
        (origin / "f.txt").write_text(str(i))
        _git("add", ".", cwd=origin)
        _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", f"c{i}", cwd=origin)
    shallow = tmp_path / "shallow"
    _git("clone", "-q", "--depth", "1", f"file://{origin}", str(shallow), cwd=tmp_path)
    cfg = REPO / ".gitleaks.toml"
    assert ss.preflight(origin, "git", cfg) == []
    assert any("shallow" in p for p in ss.preflight(shallow, "git", cfg))
    plain = tmp_path / "plain"
    plain.mkdir()
    assert any("not a git work tree" in p for p in ss.preflight(plain, "git", cfg))


# --- main() with a stand-in gitleaks ------------------------------------------

def fake_gitleaks(tmp_path: Path, report: object | None, log: str, exit_code: int = 0) -> str:
    body = "" if report is None else json.dumps(report)
    script = tmp_path / "fake-gitleaks"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(tmp_path / 'argv.json')!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        "out = sys.argv[sys.argv.index('--report-path') + 1]\n"
        f"body = {body!r}\n"
        "if body:\n"
        "    open(out, 'w').write(body)\n"
        f"sys.stderr.write({log!r})\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


OK_LOG = "INF scanned ~100 bytes (100 bytes) in 1ms\n"


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    t = tmp_path / "src"
    t.mkdir()
    (t / "a.txt").write_text("hello\n")
    return t


@pytest.mark.parametrize(
    ("report", "log", "tool_exit", "expected"),
    [
        ([], OK_LOG, 0, ss.EXIT_PASS),
        ([finding()], OK_LOG, 0, ss.EXIT_FAIL),
        ([], "INF scanned ~0 bytes (0) in 1ms\n", 0, ss.EXIT_ERROR),
        ([], "FTL unable to load gitleaks config\n", 1, ss.EXIT_ERROR),
        (None, OK_LOG, 0, ss.EXIT_ERROR),
    ],
)
def test_main_exit_codes(tmp_path: Path, target: Path, report, log, tool_exit, expected) -> None:
    fake = fake_gitleaks(tmp_path, report, log, tool_exit)
    assert ss.main([str(target), "--gitleaks", fake]) == expected


def test_default_config_is_scanned_repos_own_or_no_allowlist(tmp_path: Path) -> None:
    # A consumer repo without its own config gets default rules with NO allowlist -
    # never ShipSafe's .gitleaks.toml (which allowlists ShipSafe's fixtures/).
    assert ss.default_config(tmp_path) == ss.FALLBACK_CONFIG
    assert "allowlist" not in ss.FALLBACK_CONFIG.read_text().replace("# ", "").split("[extend]")[1]
    (tmp_path / ".gitleaks.toml").write_text('[extend]\nuseDefault = true\n')
    assert ss.default_config(tmp_path) == tmp_path / ".gitleaks.toml"


def test_main_passes_hardening_flags(tmp_path: Path, target: Path, capsys: pytest.CaptureFixture[str],
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPO)
    fake = fake_gitleaks(tmp_path, [finding()], OK_LOG)
    ss.main([str(target), "--gitleaks", fake])
    argv = json.loads((tmp_path / "argv.json").read_text())
    assert argv[0] == "dir"
    for flag in ["--redact", "--ignore-gitleaks-allow", "--no-banner"]:
        assert flag in argv
    assert argv[argv.index("--exit-code") + 1] == "0"
    # run from the repo root (as CI does), the project's own .gitleaks.toml is picked
    assert Path(argv[argv.index("--config") + 1]).resolve() == (REPO / ".gitleaks.toml").resolve()
    assert PLACEHOLDER not in capsys.readouterr().out


def test_main_gitleaksignore_blocks_scan(tmp_path: Path, target: Path) -> None:
    (target / ".gitleaksignore").write_text("a.txt:r:1\n")
    fake = fake_gitleaks(tmp_path, [], OK_LOG)
    assert ss.main([str(target), "--gitleaks", fake]) == ss.EXIT_ERROR
    assert not (tmp_path / "argv.json").exists(), "gitleaks must not even run"


def test_main_ignores_config_env_overrides(tmp_path: Path, target: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLEAKS_CONFIG", "/elsewhere.toml")
    script = tmp_path / "env-gitleaks"
    script.write_text(
        "#!/usr/bin/env python3\nimport os, sys\n"
        "out = sys.argv[sys.argv.index('--report-path') + 1]\n"
        "open(out, 'w').write('[]')\n"
        f"sys.stderr.write({OK_LOG!r})\n"
        "sys.exit(3 if 'GITLEAKS_CONFIG' in os.environ else 0)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    assert ss.main([str(target), "--gitleaks", str(script)]) == ss.EXIT_PASS


def test_main_writes_github_step_summary(tmp_path: Path, target: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    ss.main([str(target), "--gitleaks", fake_gitleaks(tmp_path, [], OK_LOG)])
    assert "Secrets scan" in summary.read_text() and "PASS" in summary.read_text()
