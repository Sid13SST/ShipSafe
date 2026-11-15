"""ShipSafe waivers: time-boxed, reviewed exceptions for gate findings.

File: .shipsafe/waivers.yml (relative to the repository being scanned).

    waivers:
      - id: CVE-2026-12345            # finding id (CVE/GHSA/PYSEC, rule id, DLxxxx, SSxxx, DS-xxxx)
        gate: container-scan          # dependency-audit | sast | dockerfile-lint | container-scan
        reason: "No Debian fix yet; tracked in issue 12; re-check weekly."
        expires: 2026-12-31           # YYYY-MM-DD, inclusive, at most 90 days ahead
        scope: zlib1g                 # optional: package name or path (glob ok) it applies to

Rules (enforced here, shared by every gate that accepts waivers):
  - An EXPIRED waiver FAILS the gate (exit 1) whether or not its finding still
    occurs, so stale exceptions cannot linger.
  - An invalid file - unknown keys, missing fields, a short reason, a bad or
    too-distant date, duplicates, YAML outside the small supported subset -
    is an ERROR (exit 2). The gate fails closed rather than guess.
  - Secrets findings cannot be waived (rotate the secret instead), and scan
    ERRORs can never be waived: a waiver only applies to a finding.
  - A waiver that matches nothing is reported as unused (does not fail).

The YAML subset is deliberately tiny (a top-level `waivers:` list of flat
key/value maps with scalar values, comments, quoted or plain strings) so the
gates stay stdlib-only and nothing in the file can be interpreted in a
surprising way.

Waivers are an exception mechanism, not a judgement that a finding is safe:
each one is a change the repository owner reviews like any other.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable, TypeVar

DEFAULT_PATH = Path(".shipsafe") / "waivers.yml"
WAIVABLE_GATES = {"dependency-audit", "sast", "dockerfile-lint", "container-scan"}
UNWAIVABLE_GATES = {"secrets": "secrets findings cannot be waived - rotate the secret; "
                               "the only suppression is the reviewed .gitleaks.toml allowlist"}
REQUIRED = ("id", "gate", "reason", "expires")
ALLOWED = set(REQUIRED) | {"scope"}
MIN_REASON = 20
MAX_DAYS = 90
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

T = TypeVar("T")


class WaiverFileError(ValueError):
    """The waivers file is not valid; the gate must ERROR."""


@dataclass(frozen=True)
class Waiver:
    id: str
    gate: str
    reason: str
    expires: date
    scope: str | None = None
    line: int = 0

    def matches(self, ids: Iterable[str], locations: Iterable[str]) -> bool:
        if self.id.lower() not in {i.lower() for i in ids if i}:
            return False
        if self.scope is None:
            return True
        scope = self.scope
        for loc in locations:
            if not loc:
                continue
            loc = loc[2:] if loc.startswith("./") else loc
            if loc == scope or fnmatch.fnmatchcase(loc, scope) or loc.startswith(scope.rstrip("/") + "/"):
                return True
        return False

    def describe(self) -> str:
        scope = f" scope={self.scope}" if self.scope else ""
        return f"{self.id}{scope} (expires {self.expires.isoformat()})"


@dataclass
class WaiverSet:
    gate: str
    active: list[Waiver] = field(default_factory=list)
    expired: list[Waiver] = field(default_factory=list)
    source: str = ""

    def expired_messages(self) -> list[str]:
        return [f"waiver {w.describe()} has EXPIRED - remove it or renew it with a fresh review"
                f" ({self.source}:{w.line})" for w in self.expired]


# --- strict YAML-subset parser ---------------------------------------------------

def _strip_comment(s: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(s):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        else:
            out.append(ch)
    if quote:
        raise WaiverFileError("unterminated quoted string")
    return "".join(out).rstrip()


def _scalar(raw: str, lineno: int) -> str:
    raw = raw.strip()
    if not raw:
        raise WaiverFileError(f"line {lineno}: empty value")
    if raw[0] in "'\"":
        if len(raw) < 2 or raw[-1] != raw[0]:
            raise WaiverFileError(f"line {lineno}: badly quoted value")
        return raw[1:-1]
    if raw[0] in "[{&*!|>%@`":
        raise WaiverFileError(f"line {lineno}: unsupported YAML value {raw!r} (use a plain or quoted string)")
    return raw


def parse(text: str) -> list[dict]:
    """Parse the waivers file into a list of {key: (value, lineno)} dicts."""
    items: list[dict] = []
    current: dict | None = None
    seen_root = False
    item_indent = key_indent = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise WaiverFileError(f"line {lineno}: tabs are not allowed")
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if not seen_root:
            if indent != 0 or body not in ("waivers:", "waivers: []"):
                raise WaiverFileError(f"line {lineno}: file must start with 'waivers:' (got {body!r})")
            seen_root = True
            if body == "waivers: []":
                seen_root = "empty"
            continue
        if seen_root == "empty":
            raise WaiverFileError(f"line {lineno}: content after 'waivers: []'")
        if indent == 0:
            raise WaiverFileError(f"line {lineno}: only one top-level key ('waivers') is allowed")
        if body.startswith("- "):
            if item_indent is None:
                item_indent = indent
            elif indent != item_indent:
                raise WaiverFileError(f"line {lineno}: inconsistent list indentation")
            current = {}
            items.append(current)
            body = body[2:].strip()
            key_indent = indent + 2
        elif current is None:
            raise WaiverFileError(f"line {lineno}: expected a list item starting with '- '")
        elif indent != key_indent:
            raise WaiverFileError(f"line {lineno}: unexpected indentation (nested values are not supported)")
        key, sep, value = body.partition(":")
        key = key.strip()
        if not sep or not re.fullmatch(r"[a-z_]+", key):
            raise WaiverFileError(f"line {lineno}: expected 'key: value'")
        if key in current:
            raise WaiverFileError(f"line {lineno}: duplicate key {key!r}")
        current[key] = (_scalar(value, lineno), lineno)
    if not seen_root:
        raise WaiverFileError("file is empty; use 'waivers: []' for no waivers")
    return items


# --- validation ---------------------------------------------------------------------

def validate(items: list[dict], today: date) -> list[Waiver]:
    waivers: list[Waiver] = []
    keys_seen: set[tuple[str, str, str | None]] = set()
    for item in items:
        first_line = min(ln for _, ln in item.values())
        where = f"waiver at line {first_line}"
        unknown = set(item) - ALLOWED
        if unknown:
            raise WaiverFileError(f"{where}: unknown key(s) {sorted(unknown)} (allowed: {sorted(ALLOWED)})")
        missing = [k for k in REQUIRED if k not in item]
        if missing:
            raise WaiverFileError(f"{where}: missing required key(s) {missing}")
        wid, gate, reason, exp = (item[k][0] for k in REQUIRED)
        scope = item["scope"][0] if "scope" in item else None
        if not ID_RE.match(wid):
            raise WaiverFileError(f"{where}: invalid id {wid!r}")
        if gate in UNWAIVABLE_GATES:
            raise WaiverFileError(f"{where}: {UNWAIVABLE_GATES[gate]}")
        if gate not in WAIVABLE_GATES:
            raise WaiverFileError(f"{where}: unknown gate {gate!r} (one of {sorted(WAIVABLE_GATES)})")
        if len(reason.strip()) < MIN_REASON:
            raise WaiverFileError(f"{where}: reason must explain the exception (>= {MIN_REASON} characters)")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp):
            raise WaiverFileError(f"{where}: expires must be YYYY-MM-DD (got {exp!r})")
        try:
            expires = date.fromisoformat(exp)
        except ValueError as exc:
            raise WaiverFileError(f"{where}: invalid date {exp!r}") from exc
        if (expires - today).days > MAX_DAYS:
            raise WaiverFileError(f"{where}: expires {exp} is more than {MAX_DAYS} days ahead; "
                                  "waivers must be re-reviewed regularly")
        if scope is not None and not scope.strip():
            raise WaiverFileError(f"{where}: scope must not be empty")
        key = (wid.lower(), gate, scope)
        if key in keys_seen:
            raise WaiverFileError(f"{where}: duplicate waiver for {wid} / {gate} / scope={scope}")
        keys_seen.add(key)
        waivers.append(Waiver(wid, gate, reason.strip(), expires, scope, first_line))
    return waivers


def load(path: Path | None, gate: str, today: date | None = None) -> WaiverSet:
    """Load the waivers for one gate. A missing file means no waivers.
    Raises WaiverFileError for anything invalid."""
    today = today or date.today()
    ws = WaiverSet(gate=gate, source=str(path) if path else "")
    if path is None or not path.exists():
        return ws
    if not path.is_file():
        raise WaiverFileError(f"{path} is not a file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WaiverFileError(f"cannot read {path}: {exc}") from exc
    try:
        all_waivers = validate(parse(text), today)
    except WaiverFileError as exc:
        raise WaiverFileError(f"{path}: {exc}") from exc
    for w in all_waivers:
        if w.gate != gate:
            continue
        (ws.expired if w.expires < today else ws.active).append(w)
    return ws


def apply(ws: WaiverSet, findings: list[T], key: Callable[[T], tuple[list[str], list[str]]],
          waivable: Callable[[T], bool] = lambda f: True) -> tuple[list[T], list[tuple[T, Waiver]], list[Waiver]]:
    """Split findings into (still failing, waived, unused waivers).
    `key(f)` returns (ids, locations) for a finding."""
    remaining: list[T] = []
    waived: list[tuple[T, Waiver]] = []
    used: set[Waiver] = set()
    for f in findings:
        match = None
        if waivable(f):
            ids, locs = key(f)
            match = next((w for w in ws.active if w.matches(ids, locs)), None)
        if match is None:
            remaining.append(f)
        else:
            waived.append((f, match))
            used.add(match)
    unused = [w for w in ws.active if w not in used]
    return remaining, waived, unused


def render_lines(waived_desc: list[str], unused: list[Waiver], expired: list[str]) -> list[str]:
    lines = [f"  - WAIVED: {d}" for d in waived_desc]
    lines += [f"  - EXPIRED WAIVER (fails the gate): {m}" for m in expired]
    lines += [f"  - unused waiver (matched nothing, consider removing): {w.describe()}" for w in unused]
    return lines
