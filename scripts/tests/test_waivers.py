"""Offline unit tests for the shared waiver mechanism."""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import waivers as wv  # noqa: E402

TODAY = date(2026, 11, 14)
REASON = "No upstream fix yet; tracked in issue 12, re-check weekly."


def doc(*items: str) -> str:
    return "waivers:\n" + "".join(items)


def item(id_="CVE-2026-1", gate="container-scan", reason=REASON, expires="2026-12-01", scope=None, extra="") -> str:
    s = f"  - id: {id_}\n    gate: {gate}\n    reason: \"{reason}\"\n    expires: {expires}\n"
    if scope is not None:
        s += f"    scope: {scope}\n"
    return s + extra


def load_text(tmp_path: Path, text: str, gate: str = "container-scan") -> wv.WaiverSet:
    p = tmp_path / "waivers.yml"
    p.write_text(text)
    return wv.load(p, gate, TODAY)


# --- parsing -------------------------------------------------------------------------

def test_missing_file_means_no_waivers(tmp_path: Path) -> None:
    ws = wv.load(tmp_path / "none.yml", "sast", TODAY)
    assert ws.active == [] and ws.expired == []


@pytest.mark.parametrize("text", ["waivers: []\n", "# header\nwaivers:\n", "waivers: []  # none yet\n"])
def test_empty_forms(tmp_path: Path, text: str) -> None:
    assert load_text(tmp_path, text).active == []


def test_committed_repo_waivers_file_is_valid_and_empty() -> None:
    repo = Path(__file__).resolve().parents[2]
    for gate in wv.WAIVABLE_GATES:
        ws = wv.load(repo / wv.DEFAULT_PATH, gate)
        assert ws.active == [] and ws.expired == []


def test_parse_full_item_with_comments_and_quotes(tmp_path: Path) -> None:
    text = ("# comment\nwaivers:\n"
            "  - id: GHSA-abcd-1234  # trailing comment\n"
            "    gate: 'dependency-audit'\n"
            "    reason: \"Contains a # hash inside quotes, which is kept\"\n"
            "    expires: 2026-12-31\n"
            "    scope: requests\n")
    (w,) = load_text(tmp_path, text, "dependency-audit").active
    assert (w.id, w.gate, w.scope, w.expires) == ("GHSA-abcd-1234", "dependency-audit", "requests", date(2026, 12, 31))
    assert "# hash" in w.reason


@pytest.mark.parametrize("text", [
    "",                                         # empty file
    "other: 1\n",                               # wrong root
    "waivers:\nextra: 1\n",                     # second top-level key
    "waivers: []\n  - id: x\n",                 # content after empty list
    "waivers:\n  id: x\n",                      # not a list item
    "waivers:\n\t- id: x\n",                    # tab
    "waivers:\n  - id: [a, b]\n",               # flow sequence
    "waivers:\n  - id: &anchor x\n",            # anchor
    "waivers:\n  - id: x\n      nested: y\n",   # nested mapping
    "waivers:\n  - id: x\n    id: y\n",         # duplicate key
    "waivers:\n  - id: \"unterminated\n",       # bad quoting
    "waivers:\n  - reason: >\n",                # block scalar
])
def test_unsupported_yaml_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(wv.WaiverFileError):
        load_text(tmp_path, text)


# --- validation ------------------------------------------------------------------------

@pytest.mark.parametrize(("kwargs", "msg"), [
    ({"gate": "secrets"}, "cannot be waived"),
    ({"gate": "nope"}, "unknown gate"),
    ({"reason": "too short"}, "reason must explain"),
    ({"expires": "31-12-2026"}, "YYYY-MM-DD"),
    ({"expires": "2026-02-30"}, "invalid date"),
    ({"expires": (TODAY + timedelta(days=91)).isoformat()}, "more than 90 days"),
    ({"id_": "bad id!"}, "invalid id"),
    ({"extra": "    owner: me\n"}, "unknown key"),
])
def test_invalid_waivers(tmp_path: Path, kwargs: dict, msg: str) -> None:
    with pytest.raises(wv.WaiverFileError, match=msg):
        load_text(tmp_path, doc(item(**kwargs)))


def test_missing_required_key(tmp_path: Path) -> None:
    with pytest.raises(wv.WaiverFileError, match="missing required"):
        load_text(tmp_path, "waivers:\n  - id: CVE-1\n    gate: sast\n")


def test_duplicate_waiver(tmp_path: Path) -> None:
    with pytest.raises(wv.WaiverFileError, match="duplicate waiver"):
        load_text(tmp_path, doc(item(), item()))


def test_exactly_90_days_is_allowed(tmp_path: Path) -> None:
    ws = load_text(tmp_path, doc(item(expires=(TODAY + timedelta(days=90)).isoformat())))
    assert len(ws.active) == 1


# --- expiry ----------------------------------------------------------------------------------

def test_expired_vs_active_and_inclusive_expiry(tmp_path: Path) -> None:
    ws = load_text(tmp_path, doc(item(id_="CVE-OLD", expires="2026-11-13"),
                                 item(id_="CVE-TODAY", expires="2026-11-14"),
                                 item(id_="CVE-NEW", expires="2026-12-01")))
    assert [w.id for w in ws.expired] == ["CVE-OLD"]
    assert [w.id for w in ws.active] == ["CVE-TODAY", "CVE-NEW"]
    assert "EXPIRED" in ws.expired_messages()[0]


def test_other_gates_waivers_are_ignored_but_still_validated(tmp_path: Path) -> None:
    ws = load_text(tmp_path, doc(item(gate="sast", id_="shipsafe.eval-exec-non-literal")), gate="container-scan")
    assert ws.active == [] and ws.expired == []
    with pytest.raises(wv.WaiverFileError):  # a broken entry for another gate still breaks every gate
        load_text(tmp_path, doc(item(gate="sast", reason="short")), gate="container-scan")


# --- matching ---------------------------------------------------------------------------------

def W(id_="CVE-1", scope=None) -> wv.Waiver:
    return wv.Waiver(id_, "container-scan", REASON, TODAY, scope)


@pytest.mark.parametrize(("waiver", "ids", "locs", "hit"), [
    (W(), ["CVE-1"], [], True),
    (W(), ["cve-1"], [], True),                                   # case-insensitive id
    (W(), ["GHSA-x", "CVE-1"], [], True),                         # alias match
    (W(), ["CVE-2"], [], False),
    (W(scope="zlib1g"), ["CVE-1"], ["zlib1g", "img (debian)"], True),
    (W(scope="zlib1g"), ["CVE-1"], ["libz"], False),
    (W(scope="demo-app"), ["CVE-1"], ["demo-app/app/main.py"], True),  # path prefix
    (W(scope="demo-app/*.py"), ["CVE-1"], ["./demo-app/x.py"], True),  # glob, ./ stripped
    (W(scope="demo-app"), ["CVE-1"], ["demo-application/x.py"], False),
])
def test_matching(waiver, ids, locs, hit) -> None:
    assert waiver.matches(ids, locs) is hit


def test_apply_splits_findings_and_reports_unused() -> None:
    ws = wv.WaiverSet("container-scan", active=[W("CVE-1"), W("CVE-9")])
    findings = [("CVE-1", "a"), ("CVE-2", "b"), ("SECRET", "c")]
    remaining, waived, unused = wv.apply(ws, findings, key=lambda f: ([f[0]], [f[1]]),
                                         waivable=lambda f: f[0] != "SECRET")
    assert remaining == [("CVE-2", "b"), ("SECRET", "c")]
    assert [(f[0], w.id) for f, w in waived] == [("CVE-1", "CVE-1")]
    assert [w.id for w in unused] == ["CVE-9"]


def test_unwaivable_findings_never_waived() -> None:
    ws = wv.WaiverSet("container-scan", active=[W("SECRET")])
    remaining, waived, _ = wv.apply(ws, ["SECRET"], key=lambda f: ([f], []), waivable=lambda f: False)
    assert remaining == ["SECRET"] and waived == []
