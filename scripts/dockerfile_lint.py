#!/usr/bin/env python3
"""ShipSafe Dockerfile gate (hadolint + a few ShipSafe policy checks).

Lints Dockerfiles with a pinned hadolint and adds four policy checks hadolint
does not make, then turns the results into a pass/fail gate result. The same
script runs locally and in CI.

Exit codes (same contract as every ShipSafe gate):
  0  PASS  - every Dockerfile was linted; nothing at warning level or above
  1  FAIL  - at least one hadolint error/warning or ShipSafe policy finding
  2  ERROR - lint incomplete or untrustworthy: no Dockerfiles found, a file
             is missing, hadolint failed or emitted invalid output, hadolint
             could not parse a file (DL1000), a file has no FROM, or a file
             under a forbidden path (fixtures/) was selected. Fails closed.

ShipSafe policy checks (all fail the gate):
  SS001  base image not pinned by digest (FROM image@sha256:...)
  SS002  final stage does not switch to a non-root USER
         (hadolint's DL3002 only fires when `USER root` is written explicitly)
  SS003  ADD with a remote URL source (unverified download into the image)
  SS004  ARG/ENV whose name looks like a secret (password/token/secret/key...)

Suppression: inline `# hadolint ignore=` pragmas are disabled
(--disable-ignore-pragma) and HADOLINT_* environment variables are removed,
so the reviewed .hadolint.yaml is the only configuration that applies.

Scope note: a PASS means "these lint rules found nothing in the Dockerfile
text". It says nothing about vulnerabilities inside the base image or the
installed packages (that is the container-scan gate's job).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / ".hadolint.yaml"

FAILING_LEVELS = {"error", "warning"}  # must match failure-threshold in .hadolint.yaml
DOCKERFILE_NAME = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|.+\.(Dockerfile|dockerfile)$")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tools"}
SECRET_NAME = re.compile(r"(?i)(passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)")
ROOT_USERS = {"root", "0"}


@dataclass
class Finding:
    path: str
    line: int
    code: str
    level: str
    message: str

    @property
    def failing(self) -> bool:
        return self.level not in {"info", "style"}


@dataclass
class LintResult:
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def failing(self) -> list[Finding]:
        return [f for f in self.findings if f.failing]

    @property
    def exit_code(self) -> int:
        if self.problems:
            return EXIT_ERROR
        return EXIT_FAIL if self.failing else EXIT_PASS


class LintError(ValueError):
    """hadolint could not be run or its output was unusable."""


# --- Dockerfile parsing for the policy checks ---------------------------------

@dataclass
class Instruction:
    line: int
    keyword: str
    args: str


def parse_instructions(text: str) -> list[Instruction]:
    """Minimal Dockerfile reader: joins backslash continuations, drops
    comments and blank lines. (Heredoc bodies are not interpreted.)"""
    out: list[Instruction] = []
    buf: list[str] = []
    start = 0
    for n, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # comment lines inside a continuation are ignored by Docker
        if not buf:
            start = n
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        joined = " ".join(p.strip() for p in buf if p.strip())
        buf = []
        keyword, _, args = joined.partition(" ")
        out.append(Instruction(start, keyword.upper(), args.strip()))
    if buf:
        joined = " ".join(p.strip() for p in buf if p.strip())
        keyword, _, args = joined.partition(" ")
        out.append(Instruction(start, keyword.upper(), args.strip()))
    return out


def _from_image(args: str) -> tuple[str, str | None]:
    tokens = [t for t in args.split() if not t.startswith("--")]
    image = tokens[0] if tokens else ""
    alias = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else None
    return image, alias


def _var_names(keyword: str, args: str) -> list[str]:
    if keyword == "ARG":
        return [args.split("=", 1)[0].strip()] if args else []
    # ENV KEY=VALUE [KEY=VALUE...]  or legacy  ENV KEY VALUE
    if "=" not in args.split(" ", 1)[0]:
        return [args.split(" ", 1)[0]] if args else []
    return [m.group(1) for m in re.finditer(r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=', args)]


def policy_findings(path: str, text: str) -> tuple[list[Finding], list[str]]:
    instrs = parse_instructions(text)
    findings: list[Finding] = []
    problems: list[str] = []
    froms = [i for i in instrs if i.keyword == "FROM"]
    if not froms:
        problems.append(f"{path}: no FROM instruction (empty or not a Dockerfile) - nothing was really linted")
        return findings, problems

    stage_names: set[str] = set()
    last_user: Instruction | None = None
    for ins in instrs:
        if ins.keyword == "FROM":
            image, alias = _from_image(ins.args)
            last_user = None  # USER does not carry across stages
            is_stage_ref = image.lower() in stage_names
            if alias:
                stage_names.add(alias.lower())
            if image.lower() != "scratch" and not is_stage_ref and "@sha256:" not in image:
                findings.append(Finding(path, ins.line, "SS001", "error",
                                        f"Base image '{image}' is not pinned by digest; use image:tag@sha256:<digest>"))
        elif ins.keyword == "USER":
            last_user = ins
        elif ins.keyword == "ADD":
            srcs = [t for t in ins.args.split() if not t.startswith("--")][:-1]
            if any(re.match(r"(?i)^(https?|ftp)://", s) for s in srcs):
                findings.append(Finding(path, ins.line, "SS003", "error",
                                        "ADD from a remote URL downloads unverified content; download with a checksum check in RUN, or COPY a vetted file"))
        if ins.keyword in ("ARG", "ENV"):
            for name in _var_names(ins.keyword, ins.args):
                if SECRET_NAME.search(name):
                    findings.append(Finding(path, ins.line, "SS004", "error",
                                            f"{ins.keyword} {name} looks like a secret; build args and ENV are stored in image metadata. Use BuildKit secret mounts"))

    final_line = froms[-1].line
    if last_user is None:
        findings.append(Finding(path, final_line, "SS002", "error",
                                "Final stage never sets USER, so the container runs as root; add a non-root USER"))
    else:
        user = last_user.args.split(":", 1)[0].strip().lower()
        if user in ROOT_USERS:
            findings.append(Finding(path, last_user.line, "SS002", "error",
                                    "Final stage runs as root; switch to a non-root USER"))
    return findings, problems


# --- hadolint -------------------------------------------------------------------

def parse_hadolint(output: str, path: str) -> tuple[list[Finding], list[str]]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise LintError(f"hadolint output for {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise LintError(f"hadolint output for {path} is not a JSON list")
    findings, problems = [], []
    for item in data:
        if not isinstance(item, dict) or "code" not in item or "level" not in item:
            raise LintError(f"malformed hadolint finding for {path}: {item!r}")
        code, level = str(item["code"]), str(item["level"]).lower()
        msg = " ".join(str(item.get("message", "")).split())
        if code == "DL1000":
            problems.append(f"{path}: hadolint could not parse the file ({msg[:160]})")
            continue
        findings.append(Finding(path, int(item.get("line") or 0), code, level, msg))
    return findings, problems


def run_hadolint(hadolint: str, config: Path, path: str) -> str:
    cmd = [
        hadolint,
        "--config", str(config),     # explicit config; no ~/.config or cwd lookup
        "--disable-ignore-pragma",   # inline `# hadolint ignore=` doesn't count
        "--no-fail",                 # findings are judged from the JSON output
        "--no-color",
        "--format", "json",
        path,
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith("HADOLINT_")}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:  # with --no-fail, non-zero means hadolint itself failed
        raise LintError(f"hadolint exited {proc.returncode} on {path}: {proc.stderr.strip().splitlines()[0] if proc.stderr.strip() else ''}")
    return proc.stdout


def discover(root: Path, excludes: list[str]) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv"))
        for name in sorted(filenames):
            if DOCKERFILE_NAME.match(name):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if not any(_under(rel, ex) for ex in excludes):
                    found.append(rel if root == Path(".") else os.path.join(str(root), rel))
    return found


def _under(path: str, prefix: str) -> bool:
    p = path[2:] if path.startswith("./") else path
    pre = prefix.rstrip("/")
    return p == pre or p.startswith(pre + "/")


def lint(files: list[str], config: Path, hadolint: str, forbid: list[str]) -> LintResult:
    result = LintResult(files=list(files))
    if not config.is_file():
        result.problems.append(f"hadolint config not found: {config}")
    if not files:
        result.problems.append("no Dockerfiles selected (wrong target or everything excluded)")
    for path in files:
        if any(_under(path, fb) for fb in forbid):
            result.problems.append(f"{path} is under a forbidden path ({', '.join(forbid)})")
    if result.problems:
        return result
    for path in files:
        if not Path(path).is_file():
            result.problems.append(f"{path}: file not found")
            continue
        found, problems = parse_hadolint(run_hadolint(hadolint, config, path), path)
        result.findings += found
        result.problems += problems
        p_found, p_problems = policy_findings(path, Path(path).read_text(encoding="utf-8", errors="replace"))
        result.findings += p_found
        result.problems += p_problems
    result.findings.sort(key=lambda f: (f.path, f.line, f.code))
    return result


def render(result: LintResult, label: str) -> str:
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}[result.exit_code]
    lines = [f"dockerfile-lint [{label}]: {verdict} - {len(result.files)} Dockerfile(s), "
             f"{len(result.failing)} failing finding(s), {len(result.findings) - len(result.failing)} informational"]
    for f in result.findings:
        tag = "" if f.failing else " (informational, does not fail)"
        lines.append(f"  - {f.path}:{f.line} [{f.level}] {f.code} {f.message[:110]}{tag}")
    for p in result.problems:
        lines.append(f"  - LINT PROBLEM: {p}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dockerfiles", nargs="*", help="Dockerfiles to lint (or use --discover)")
    parser.add_argument("--discover", type=Path, help="find Dockerfiles under this directory")
    parser.add_argument("--exclude", action="append", default=[], help="path prefix to skip during discovery (repeatable)")
    parser.add_argument("--forbid-path", action="append", default=[], help="ERROR if a selected file is under this path (repeatable)")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="hadolint config (default: .hadolint.yaml)")
    parser.add_argument("--hadolint", default="hadolint", help="hadolint executable")
    args = parser.parse_args(argv)

    files = list(args.dockerfiles)
    if args.discover is not None:
        files += discover(args.discover, args.exclude)
    label = f"discover {args.discover}" if args.discover is not None else " ".join(args.dockerfiles)
    try:
        result = lint(files, args.config, args.hadolint, args.forbid_path)
        text, code = render(result, label), result.exit_code
    except (LintError, OSError) as exc:
        text, code = f"dockerfile-lint [{label}]: ERROR - {exc}", EXIT_ERROR
    print(text)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("### Dockerfile lint (hadolint + ShipSafe policy)\n\n```\n" + text + "\n```\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
