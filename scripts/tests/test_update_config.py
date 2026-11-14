"""Dependabot and binary-pin freshness cover every pin type in the repo."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def updates() -> list[str]:
    text = (REPO / ".github" / "dependabot.yml").read_text()
    assert re.search(r"^version: 2$", text, re.M)
    return re.split(r"\n  - package-ecosystem: ", text)[1:]


def test_dependabot_covers_actions_pip_and_docker() -> None:
    blocks = updates()
    seen = {(b.split()[0], re.search(r"directory: (\S+)", b).group(1)) for b in blocks}
    assert seen == {("github-actions", "/"), ("pip", "/scripts"), ("pip", "/demo-app"), ("docker", "/demo-app")}


def test_every_dependabot_update_has_a_cooldown() -> None:
    for b in updates():
        assert re.search(r"cooldown:\n\s+default-days: [1-9]\d*", b), b.split()[0]


def test_binary_freshness_check_covers_every_install_script() -> None:
    check = (REPO / "scripts" / "check_binary_pins.sh").read_text()
    for script in sorted((REPO / "scripts").glob("install_*.sh")):
        assert f"|{script.name}|" in check, f"{script.name} is not covered by check_binary_pins.sh"
        var = re.search(r'^([A-Z]+_VERSION)="\d+\.\d+\.\d+"$', script.read_text(), re.M)
        assert var and f"|{var.group(1)}|" in check, script.name
