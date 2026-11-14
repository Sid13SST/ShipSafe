"""Structural checks on the workflows (text-based; no YAML library needed)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WF = REPO / ".github" / "workflows"
REUSABLE = ["dependency-audit", "sast", "secrets", "dockerfile-lint", "container-scan"]
ALL = sorted(WF.glob("*.yml")) + sorted((REPO / "docs" / "examples").glob("*.yml"))


def code(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def tooling_block(text: str) -> str:
    start = text.index("      - name: Resolve ShipSafe tooling ref")
    end = text.index('rev-parse HEAD) from $TOOLING_REPO"', start)
    return text[start:end]


@pytest.mark.parametrize("name", REUSABLE)
def test_reusable_workflow_runs_scripts_from_pinned_tooling(name: str) -> None:
    text = (WF / f"{name}.yml").read_text()
    body = code(text)
    assert "workflow_call:" in body
    for key in ("tooling-repository:", "tooling-ref:", "tooling-token:"):
        assert key in body, key
    # every script/tool invocation goes through the tooling checkout
    for line in body.splitlines():
        if re.search(r"(^|[\s\"'=(])scripts/", line):
            pytest.fail(f"{name}: bare scripts/ reference: {line.strip()}")
    assert '"$SHIPSAFE/scripts/' in body
    # tooling is moved out of the workspace before anything uses it
    assert body.index('mv .shipsafe-tooling "$RUNNER_TEMP/shipsafe"') < body.index('"$SHIPSAFE/scripts/')
    # cross-repo use requires a full commit SHA
    assert "^[0-9a-f]{40}$" in body


def test_tooling_steps_identical_in_all_reusable_workflows() -> None:
    blocks = {name: tooling_block((WF / f"{name}.yml").read_text()) for name in REUSABLE}
    first = blocks[REUSABLE[0]]
    for name, block in blocks.items():
        assert block == first, f"{name}: tooling steps drifted from {REUSABLE[0]}"


@pytest.mark.parametrize("wf", ALL, ids=lambda p: p.name)
def test_actions_pinned_by_sha_and_least_privilege(wf: Path) -> None:
    body = code(wf.read_text())
    for ref in re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", body, re.M):
        if ref.startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", ref), f"{wf.name}: not pinned to a full SHA: {ref}"
    assert "persist-credentials: true" not in body
    for m in re.finditer(r"uses: actions/checkout@\S+[^\n]*\n((?:\s{8,}[^\n]+\n)*)", wf.read_text()):
        assert "persist-credentials: false" in m.group(1), f"{wf.name}: checkout without persist-credentials: false"
    assert re.search(r"^permissions:\s*\n\s+contents: read\s*$", body, re.M), f"{wf.name}: top-level permissions"
    assert not re.search(r"\b(write-all|contents: write|id-token: write)\b", body)


def test_secrets_workflow_never_defaults_to_tooling_allowlist() -> None:
    text = (WF / "secrets.yml").read_text()
    m = re.search(r"      config:\n(?:        [^\n]*\n)*?        default: \"([^\"]*)\"", text)
    assert m and m.group(1) == "", "secrets.yml config must default to empty (scanned repo's own config)"


def _resolve_script() -> str:
    text = (WF / "dependency-audit.yml").read_text()
    block = tooling_block(text)
    run = block[block.index("        run: |\n") + len("        run: |\n"):block.index("      - name: Check out ShipSafe tooling")]
    return "\n".join(l[10:] for l in run.splitlines())


SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(("tooling_repo", "ref", "ok"), [
    ("Sid13SST/ShipSafe", "0123abc", True),          # same repo (ShipSafe's own CI): any ref
    ("Sid13SST/ShipSafe", SHA, True),
    ("other/consumer", SHA, True),                   # cross-repo with a full SHA
    ("other/consumer", "main", False),               # cross-repo with a branch
    ("other/consumer", "v1.2.0", False),             # ... a tag
    ("other/consumer", SHA[:12], False),             # ... a short SHA
    ("other/consumer", SHA.upper(), False),          # ... not lowercase hex
])
def test_tooling_ref_validation(tmp_path: Path, tooling_repo: str, ref: str, ok: bool) -> None:
    import subprocess
    out = tmp_path / "out"
    out.write_text("")
    env = {"PATH": "/usr/bin:/bin", "GITHUB_OUTPUT": str(out), "TOOLING_REF": ref,
           "TOOLING_REPO": tooling_repo if tooling_repo != "other/consumer" else "Sid13SST/ShipSafe",
           "CALLER_REPO": "Sid13SST/ShipSafe" if tooling_repo != "other/consumer" else "other/consumer"}
    proc = subprocess.run(["bash", "-c", _resolve_script()], env=env, capture_output=True, text=True)
    assert (proc.returncode == 0) is ok, proc.stdout + proc.stderr
    if ok:
        assert f"ref={ref}" in out.read_text()
    else:
        assert "must be a full 40-character commit SHA" in proc.stdout
