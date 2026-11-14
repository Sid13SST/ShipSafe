"""Offline unit tests for the Dockerfile gate (no hadolint binary, no docker)."""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dockerfile_lint as dl  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PINNED = "python:3.13.18-slim-trixie@sha256:" + "a" * 64


def codes(text: str) -> list[str]:
    findings, problems = dl.policy_findings("Dockerfile", text)
    assert not problems
    return sorted(f.code for f in findings)


# --- reviewed config / pins ---------------------------------------------------

def test_hadolint_config_only_sets_warning_threshold() -> None:
    lines = [l.strip() for l in (REPO / ".hadolint.yaml").read_text().splitlines()
             if l.strip() and not l.strip().startswith("#")]
    assert lines == ["failure-threshold: warning"], "no ignored/override/trustedRegistries allowed"
    assert dl.FAILING_LEVELS == {"error", "warning"}


def test_installer_pins_version_and_all_checksums() -> None:
    text = (REPO / "scripts" / "install_hadolint.sh").read_text()
    assert re.search(r'^HADOLINT_VERSION="\d+\.\d+\.\d+"$', text, re.M)
    assert len(re.findall(r'(linux|macos)-(x86_64|arm64)\)\s+echo "([0-9a-f]{64})"', text)) == 4


def test_demo_dockerfile_passes_policy_and_pins_digest() -> None:
    text = (REPO / "demo-app" / "Dockerfile").read_text()
    assert codes(text) == []
    assert re.search(r"^FROM \S+:\d+\.\d+\.\d+-slim-\w+@sha256:[0-9a-f]{64}$", text, re.M)


def test_fixture_triggers_every_policy_check() -> None:
    text = (REPO / "fixtures" / "dockerfile" / "Dockerfile.vulnerable").read_text()
    assert codes(text) == ["SS001", "SS002", "SS003", "SS004"]


# --- Dockerfile parsing --------------------------------------------------------

def test_parse_joins_continuations_and_skips_comments() -> None:
    text = "# c\nFROM x\nRUN a \\\n  # inner comment\n  && b\n\nUSER 1\n"
    ins = dl.parse_instructions(text)
    assert [(i.line, i.keyword) for i in ins] == [(2, "FROM"), (3, "RUN"), (7, "USER")]
    assert ins[1].args == "a && b"


# --- SS001 base image digest ---------------------------------------------------

@pytest.mark.parametrize("image", ["python", "python:3.13", "python:latest", "ghcr.io/x/y:1.0"])
def test_unpinned_base_image(image: str) -> None:
    assert "SS001" in codes(f"FROM {image}\nUSER 1000\n")


def test_pinned_scratch_and_stage_refs_ok() -> None:
    text = f"FROM {PINNED} AS build\nFROM --platform=linux/amd64 build AS second\nFROM scratch\nUSER 1000\n"
    assert codes(text) == []


# --- SS002 non-root final stage ------------------------------------------------

@pytest.mark.parametrize("user_line", ["", "USER root\n", "USER 0\n", "USER root:root\n", "USER 0:0\n"])
def test_root_final_stage(user_line: str) -> None:
    assert "SS002" in codes(f"FROM {PINNED}\n{user_line}")


def test_user_does_not_carry_across_stages() -> None:
    assert "SS002" in codes(f"FROM {PINNED} AS b\nUSER 1000\nFROM {PINNED}\n")


@pytest.mark.parametrize("user", ["10001", "10001:10001", "app", "app:app"])
def test_non_root_user_ok(user: str) -> None:
    assert codes(f"FROM {PINNED}\nUSER {user}\n") == []


def test_last_user_wins() -> None:
    assert "SS002" in codes(f"FROM {PINNED}\nUSER app\nUSER root\n")
    assert codes(f"FROM {PINNED}\nUSER root\nRUN x\nUSER app\n") == []


# --- SS003 ADD from URL ----------------------------------------------------------

@pytest.mark.parametrize("src", ["https://example.invalid/a.tgz", "http://example.invalid/a", "ftp://example.invalid/a"])
def test_add_remote_url(src: str) -> None:
    assert "SS003" in codes(f"FROM {PINNED}\nADD --chown=1:1 {src} /opt/\nUSER 1\n")


def test_add_local_and_copy_ok() -> None:
    assert codes(f"FROM {PINNED}\nADD files.tar.gz /opt/\nCOPY a /b\nUSER 1\n") == []


# --- SS004 secret-looking ARG/ENV ------------------------------------------------

@pytest.mark.parametrize(
    "line",
    ["ARG GITHUB_TOKEN", "ARG DB_PASSWORD=x", "ENV API_KEY=x", "ENV A=1 CLIENT_SECRET=x",
     "ENV AWS_ACCESS_KEY abc", "ARG PRIVATE_KEY", "ENV db_passwd=x"],
)
def test_secret_named_build_vars(line: str) -> None:
    assert "SS004" in codes(f"FROM {PINNED}\n{line}\nUSER 1\n")


@pytest.mark.parametrize("line", ["ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1", "ARG VERSION=1", "ENV PATH=/x:$PATH"])
def test_benign_build_vars_ok(line: str) -> None:
    assert codes(f"FROM {PINNED}\n{line}\nUSER 1\n") == []


def test_arg_before_from_is_checked() -> None:
    assert "SS004" in codes(f"ARG NPM_TOKEN\nFROM {PINNED}\nUSER 1\n")


def test_no_from_is_problem() -> None:
    for text in ["", "# only a comment\n", "RUN echo hi\n"]:
        assert dl.policy_findings("Dockerfile", text)[1]


# --- hadolint output parsing ------------------------------------------------------

def test_parse_hadolint_levels_and_parse_failure() -> None:
    out = json.dumps([
        {"code": "DL3008", "level": "warning", "line": 3, "message": "pin"},
        {"code": "DL3009", "level": "info", "line": 3, "message": "lists"},
        {"code": "DL1000", "level": "error", "line": 1, "message": "unexpected 't'"},
    ])
    findings, problems = dl.parse_hadolint(out, "D")
    assert [(f.code, f.failing) for f in findings] == [("DL3008", True), ("DL3009", False)]
    assert problems and "could not parse" in problems[0]


@pytest.mark.parametrize("bad", ["", "not json", "{}", "[1]", '[{"code": "X"}]'])
def test_parse_hadolint_malformed(bad: str) -> None:
    with pytest.raises(dl.LintError):
        dl.parse_hadolint(bad, "D")


# --- discovery / forbid -------------------------------------------------------------

def test_discover_names_excludes_and_skips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for rel in ["Dockerfile", "svc/Dockerfile.prod", "svc/api.Dockerfile", "Containerfile",
                "fixtures/dockerfile/Dockerfile.vulnerable", ".venv-tools/x/Dockerfile",
                ".git/Dockerfile", "docs/notes.md", "svc/Dockerfiles.txt"]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("FROM x\n")
    monkeypatch.chdir(tmp_path)
    assert dl.discover(Path("."), ["fixtures/"]) == ["Containerfile", "Dockerfile", "svc/Dockerfile.prod", "svc/api.Dockerfile"]


def test_forbidden_and_empty_selection_are_errors() -> None:
    cfg = REPO / ".hadolint.yaml"
    assert dl.lint(["fixtures/dockerfile/Dockerfile.vulnerable"], cfg, "unused", ["fixtures/"]).exit_code == dl.EXIT_ERROR
    assert dl.lint([], cfg, "unused", []).exit_code == dl.EXIT_ERROR


# --- main() with a stand-in hadolint -------------------------------------------------

def fake_hadolint(tmp_path: Path, output: str, exit_code: int = 0) -> str:
    script = tmp_path / "fake-hadolint"
    script.write_text(
        "#!/usr/bin/env python3\nimport json, os, sys\n"
        f"open({str(tmp_path / 'call.json')!r}, 'w').write(json.dumps("
        "{'argv': sys.argv[1:], 'env': sorted(k for k in os.environ if k.startswith('HADOLINT_'))}))\n"
        f"sys.stdout.write({output!r})\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture()
def clean_dockerfile(tmp_path: Path) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(f"FROM {PINNED}\nUSER 10001\n")
    return p


@pytest.mark.parametrize(
    ("output", "tool_exit", "expected"),
    [
        ("[]", 0, dl.EXIT_PASS),
        ('[{"code":"DL3009","level":"info","line":1,"message":"m"}]', 0, dl.EXIT_PASS),
        ('[{"code":"DL3008","level":"warning","line":1,"message":"m"}]', 0, dl.EXIT_FAIL),
        ('[{"code":"DL1000","level":"error","line":1,"message":"m"}]', 0, dl.EXIT_ERROR),
        ("[]", 1, dl.EXIT_ERROR),
        ("garbage", 0, dl.EXIT_ERROR),
    ],
)
def test_main_exit_codes(tmp_path: Path, clean_dockerfile: Path, output: str, tool_exit: int, expected: int) -> None:
    assert dl.main([str(clean_dockerfile), "--hadolint", fake_hadolint(tmp_path, output, tool_exit)]) == expected


def test_main_policy_findings_fail_even_if_hadolint_clean(tmp_path: Path) -> None:
    p = tmp_path / "Dockerfile"
    p.write_text("FROM python:3.13-slim\n")
    assert dl.main([str(p), "--hadolint", fake_hadolint(tmp_path, "[]")]) == dl.EXIT_FAIL


def test_main_flags_and_env(tmp_path: Path, clean_dockerfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HADOLINT_IGNORE", "DL3008")
    monkeypatch.setenv("HADOLINT_FAILURE_THRESHOLD", "none")
    dl.main([str(clean_dockerfile), "--hadolint", fake_hadolint(tmp_path, "[]")])
    call = json.loads((tmp_path / "call.json").read_text())
    for flag in ["--disable-ignore-pragma", "--no-fail", "--no-color"]:
        assert flag in call["argv"]
    assert call["argv"][call["argv"].index("--config") + 1] == str(REPO / ".hadolint.yaml")
    assert call["argv"][call["argv"].index("--format") + 1] == "json"
    assert call["env"] == [], "HADOLINT_* env must not reach hadolint"


def test_main_missing_file_and_config(tmp_path: Path) -> None:
    fake = fake_hadolint(tmp_path, "[]")
    assert dl.main([str(tmp_path / "nope"), "--hadolint", fake]) == dl.EXIT_ERROR
    p = tmp_path / "Dockerfile"
    p.write_text(f"FROM {PINNED}\nUSER 1\n")
    assert dl.main([str(p), "--config", str(tmp_path / "x.yaml"), "--hadolint", fake]) == dl.EXIT_ERROR


def test_main_writes_github_step_summary(tmp_path: Path, clean_dockerfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    dl.main([str(clean_dockerfile), "--hadolint", fake_hadolint(tmp_path, "[]")])
    assert "Dockerfile lint" in summary.read_text() and "PASS" in summary.read_text()
