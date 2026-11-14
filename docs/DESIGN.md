# ShipSafe design

## Goal

Show, in a small and reviewable repository, how to run common open-source
security checks as **pass/fail gates** in GitHub Actions - and prove each gate
actually blocks on a real issue, not just that it runs.

## What ShipSafe is and is not

ShipSafe **is**:

- A set of automated checks that run in CI and fail the build on findings.
- A demo of how to wire those checks so they are reproducible locally.
- A self-testing setup: every gate is run against a seeded vulnerable fixture
  and CI fails if the gate does not catch it.

ShipSafe **is not**:

- A security guarantee, certification, or substitute for review, threat
  modelling, or penetration testing.
- Complete coverage. Each tool sees only what its rules and data cover. Known
  blind spots are listed per gate below.
- A scanner for anything other than this repository. Fixtures are never
  pointed at real targets.

## Architecture

```
            push / pull_request
                    |
                 ci.yml
   +----------+-----+------------+----------------------+
   |          |                  |                      |
demo-app   gate unit     gate on demo-app        gate self-test
 tests      tests      (reusable workflow)   (scripts/verify_*.sh)
                              |                      |
                     scripts/<gate>.py  <-----  same script, run on
                              |                 demo-app AND fixtures/
                        tool (pip-audit, ...)   asserts PASS / FAIL / ERROR
```

- **Reusable workflow per gate** (`.github/workflows/<gate>.yml`,
  `on: workflow_call`). Thin: check out, install pinned tool, call the script.
- **Gate script per gate** (`scripts/<gate>.py`). Runs the tool, parses its
  machine-readable output, prints a summary (also to the GitHub step summary),
  and returns a stable exit code. Used identically by CI and locally.
- **Fixture per gate** (`fixtures/<gate>/`). Minimal deliberately vulnerable
  input with a documented expected finding.
- **Self-test per gate** (`scripts/verify_<gate>.sh`). Asserts the gate passes
  on the demo app, fails on the fixture with the expected findings, and errors
  (fails closed) on unauditable input.

### Exit-code contract

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | PASS | Tool ran fully; no findings above the gate threshold |
| 1 | FAIL | Findings reported |
| 2 | ERROR | Tool or input problem; audit incomplete. Treated as a failure |

Failing closed matters: a gate that silently errors and exits 0 gives false
confidence, which is worse than no gate.

## Gates

### 1. Dependency audit - pip-audit (implemented, Batch 1)

- **Input:** fully pinned requirements files (`demo-app/requirements.txt`,
  `demo-app/requirements-dev.txt`).
- **How:** `pip-audit -r <file> --no-deps --disable-pip -f json`. Nothing is
  installed; only the listed `name==version` pins are checked against the
  PyPI JSON API advisory data (sourced from the PyPA advisory database / OSV).
- **Fails on:** any advisory matching a pin (no severity threshold - pip-audit's
  PyPI source does not provide consistent severity).
- **Errors on:** unpinned requirements, packages that cannot be audited
  (e.g. not on PyPI), tool failure, missing/invalid report.
- **Fixture:** `fixtures/dependency-audit/vulnerable-requirements.txt` -
  old `requests`, `jinja2`, `pyyaml`, `urllib3` pins with published advisories.
- **Blind spots / honest notes:**
  - Only *known, published* advisories. Zero-days and unreported issues pass.
  - Results change over time: a new advisory can turn a previously green app
    red with no code change. That is intended behaviour, but it means CI is not
    perfectly reproducible across days.
  - Checks only pins listed in the files. It relies on the files being a
    complete lock; it does not inspect what is actually installed in an image
    (Trivy covers the image in a later batch).
  - Does not judge reachability: a flagged advisory may not be exploitable in
    this app.
  - No allowlist/waiver mechanism yet (planned; waivers must carry an expiry
    and reason).

### 2. SAST - Semgrep (planned)

Semgrep OSS CLI with pinned, vendored open rules (Python/FastAPI), run on
`demo-app/`; fixture with e.g. `subprocess(..., shell=True)` on user input and
`yaml.load` without a safe loader. Blind spots: pattern-based, intra-file for
the OSS engine, misses business-logic flaws.

### 3. Secrets detection - Gitleaks (planned)

Gitleaks on the working tree (and history for pushes). Fixture uses obviously
fake, non-functional tokens in a format that matches default rules; the app
scan excludes `fixtures/` via config. Blind spots: only pattern/entropy
matches; secrets in unscanned places (CI variables, other repos) are out of
scope.

### 4. Dockerfile lint - hadolint (planned)

hadolint on `demo-app/Dockerfile` with a failure threshold of `warning`;
fixture Dockerfile with `latest` tags, `ADD` of URLs, running as root.

### 5. Container image scan - Trivy (planned)

Build the demo image in CI, scan with Trivy for OS and language package
vulnerabilities (fail on HIGH/CRITICAL with fixes available) and
misconfiguration. Fixture: an old pinned base image reference scanned as
config/image. Blind spots: advisory-data dependent, same time-variance as
pip-audit.

## Supply-chain hygiene for the pipeline itself

- Third-party actions pinned to full commit SHAs.
- Tool versions pinned in `scripts/requirements-tools.txt` (later batches may
  add hashes).
- Least-privilege `permissions:`; `persist-credentials: false` on checkout.
- These reduce risk; they do not eliminate it (e.g. pinned tools can still have
  bugs, PyPI packages are not hash-pinned yet).

## Reuse

Batch 1's reusable workflow is designed for use *within this repository*
(`uses: ./.github/workflows/dependency-audit.yml`) because it runs scripts from
the checked-out repo. Cross-repository reuse (checking out ShipSafe's scripts
at a pinned ref, or packaging as a composite action) is a later batch.
