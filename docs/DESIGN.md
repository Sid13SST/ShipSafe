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

### Policy defaults (for the repository owner to review)

Each gate's FAIL threshold below is **ShipSafe's chosen default**, picked so
that a red build points at something a developer can act on in that change.
It is not a security guarantee, and it is **not a statement that anything
below the threshold is acceptable risk** - that judgement belongs to whoever
owns the system, and the repository owner reviews these defaults like any
other change. Findings below a threshold are still reported in every run
precisely so that someone can make that call.

| Gate | FAILs on (default) | Reported only (default) |
|------|--------------------|-------------------------|
| Dependency audit | any published advisory matching a pin | - |
| SAST | ERROR/WARNING (and CRITICAL/HIGH/MEDIUM/unknown) rule severity | INFO/LOW |
| Secrets | any finding | - |
| Dockerfile lint | hadolint warning/error; ShipSafe SS001-SS004 | hadolint info/style |
| Container scan | HIGH/CRITICAL vulns **with a fixed version**; any misconfiguration; image secrets; EOL OS | vulns with no fix yet (any severity); LOW/MEDIUM/UNKNOWN |

Changing a threshold is a code change in the gate script (and its tests),
not a configuration switch, so it is always visible in review. Individual,
time-boxed exceptions go through waivers (next section), never through
lowering a threshold.

### Waivers

`.shipsafe/waivers.yml` in the scanned repository holds time-boxed
exceptions for individual findings. Shared logic: `scripts/waivers.py`.

```yaml
waivers:
  - id: CVE-2026-12345        # CVE/GHSA/PYSEC, Semgrep rule id, DLxxxx/SSxxx, DS-xxxx
    gate: container-scan      # dependency-audit | sast | dockerfile-lint | container-scan
    reason: "No Debian fix yet; image not internet-facing; issue 12"
    expires: 2026-12-31       # YYYY-MM-DD, inclusive, at most 90 days ahead
    scope: zlib1g             # optional: package name, or path/glob for SAST/Dockerfile
```

- **Expired waiver -> FAIL** (exit 1), even if its finding no longer occurs,
  so stale exceptions are removed or consciously renewed.
- **Invalid file -> ERROR** (exit 2): unknown or missing keys, a reason under
  20 characters, a bad date, an expiry more than 90 days ahead, duplicates,
  or any YAML outside a deliberately tiny subset (flat key/value items,
  comments, plain or quoted strings - no anchors, flow collections, block
  scalars or nesting). A broken entry for any gate breaks every gate.
- **Not waivable:** secrets findings (rotate the secret; the reviewed
  `.gitleaks.toml` allowlist is the only suppression), image secrets and
  end-of-support OS findings in the container scan, and scan ERRORs of any
  kind - a waiver applies to a finding, never to an incomplete scan.
- Waived findings are still printed (`WAIVED: ... until <date> (<reason>)`),
  and waivers that matched nothing are reported as unused.
- Waivers are the **only** per-finding suppression. Inline tool comments
  (`# nosemgrep`, `# hadolint ignore=`, `gitleaks:allow`, `trivy:ignore`)
  and tool ignore files (`.semgrepignore`, `.gitleaksignore`, `.trivyignore`)
  are ignored or make the gate ERROR, because they bypass review.
- A waiver records a reviewed, temporary exception; it does not make the
  finding safe. `scripts/verify_waivers.sh` (CI `waivers-self-test`) checks
  these rules with the real tools.

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
  - Individual advisories can be waived for at most 90 days (see Waivers);
    there is no permanent ignore list.

### 2. SAST - Semgrep (implemented, Batch 2)

- **Tool:** Semgrep OSS CLI, pinned (`semgrep==1.185.0`), run with
  `--oss-only --metrics=off --disable-version-check` and a local `--config`
  only. No account, token, registry rules, or network access is used.
- **Rules:** `rules/semgrep/python-security.yml`, 10 hand-written, reviewed
  rules. Each has positive and negative cases in
  `rules/semgrep/python-security.py`, checked by `semgrep --test`.

  | Rule | Severity | Catches |
  |------|----------|---------|
  | `fastapi-input-to-shell` | ERROR | taint: FastAPI route param -> `subprocess(..., shell=True)` / `os.system` / `os.popen` |
  | `subprocess-shell-true` | WARNING | any `subprocess.*(..., shell=True)` |
  | `os-system-non-literal` | ERROR | `os.system`/`os.popen` with a non-constant command |
  | `yaml-unsafe-load` | ERROR | `yaml.load` without a safe Loader, `yaml.unsafe_load` |
  | `eval-exec-non-literal` | ERROR | `eval`/`exec` of a non-constant |
  | `sql-string-formatting` | ERROR | `execute()` with f-string / `%` / `.format` / `+` SQL |
  | `pickle-load` | WARNING | `pickle.load(s)` |
  | `requests-verify-false` | WARNING | `requests.*(..., verify=False)` |
  | `fastapi-cors-wildcard-credentials` | WARNING | CORS `allow_origins=["*"]` with credentials |
  | `weak-hash` | INFO | `hashlib.md5` / `sha1` (reported, never fails) |

- **Target:** the repository root, so new code is scanned by default, with
  explicit `--exclude fixtures/` and `--exclude rules/semgrep/python-security.py`
  (both deliberately vulnerable). `--forbid-path fixtures/` makes the gate
  ERROR if a fixture is scanned anyway, so a broken or removed exclude gives
  a clear error instead of mixing fixture findings into the project result.
- **Fails on:** any finding with severity ERROR or WARNING (and the newer
  CRITICAL/HIGH/MEDIUM names, or any severity it does not recognise).
  INFO/LOW findings are reported but do not fail.
- **Errors on (fails closed):** semgrep non-zero exit or missing/invalid
  report, any entry in the report's `errors`, skipped rules, zero files
  scanned, a forbidden path scanned, or a scanned `.py` file that Python's
  `ast` cannot parse.
- **Fixture:** `fixtures/sast/vulnerable_app.py` - FastAPI handlers with
  command injection, `yaml.load`, `eval`, f-string SQL and `pickle.loads`. The
  first statement raises, so it cannot be imported or run.
- **Blind spots / honest notes:**
  - Pattern matching over a small rule set. Anything the 10 rules don't
    describe - auth flaws, business logic, SSRF, path traversal, most
    framework-specific issues - passes.
  - Semgrep OSS taint tracking is intra-procedural: input passed through a
    helper function before reaching a shell is caught only by the generic
    (non-taint) rules, if at all.
  - Semgrep skips `tests/` directories by default, so test code is not
    scanned (tracked as a decision in TASKS.md).
  - Semgrep 1.185.0 reports no error for files it cannot parse (its parser
    recovers silently). The gate compensates for Python with its own `ast`
    check; non-Python files get no such check.
  - The `ast` check uses the runner's Python (3.13); code using newer syntax
    would be reported as ERROR.
  - False positives are possible (e.g. `shell=True` with a constant command
    still raises a WARNING). They are handled with a time-boxed waiver.
    Inline `# nosemgrep` comments are ignored (`--disable-nosem`) and a
    `.semgrepignore` makes the gate ERROR - both silently bypassed the gate
    before Batch 6 (found and closed while building waivers).

### 3. Secrets detection - Gitleaks (implemented, Batch 3)

- **Tool:** Gitleaks 8.30.1 OSS CLI (MIT). Installed by
  `scripts/install_gitleaks.sh`, which pins the version and the SHA-256 of
  each platform's release tarball in the repo and aborts on mismatch. The
  `gitleaks-action` is not used (it needs a licence key for organisations).
- **Rules:** Gitleaks' built-in default rule set (`[extend] useDefault = true`).
- **Target:** CI scans the **full git history** (`gitleaks git`, checkout
  with `fetch-depth: 0`), so a secret that was committed and later deleted
  still fails the gate. Locally, `--mode dir` scans the working tree,
  including uncommitted and git-ignored files.
- **Allowlist:** `.gitleaks.toml` allowlists exactly one thing, the path regex
  `^(\./)?fixtures/`. A unit test fails if the file gains any other
  suppression (regexes, stopwords, commits, rule overrides). The self-test
  scans the project with default rules and no allowlist and checks that every
  finding is under `fixtures/`, so the allowlist provably hides nothing else.
- **Suppression bypasses closed:**
  - inline `gitleaks:allow` comments are ignored (`--ignore-gitleaks-allow`);
  - Gitleaks 8.30.1 always reads a `.gitleaksignore` from the scanned
    directory, even when `--gitleaks-ignore-path` points elsewhere (verified
    while building this). The gate therefore ERRORs if one exists anywhere in
    the target, before running Gitleaks;
  - `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` are removed from the
    environment and the config is always passed explicitly.
- **Fails on:** any finding.
- **Errors on (fails closed):** missing config/target, Gitleaks non-zero exit
  (it runs with `--exit-code 0`, so non-zero means a tool error), missing or
  invalid report, "scanned ~0 bytes" or no volume line in the log, 0 commits
  in git mode, git mode on a shallow clone or non-repository, `.gitleaksignore`
  present.
- **Output:** rule id, file, line and commit only. `--redact` keeps secret
  values out of Gitleaks' logs and report; no report is uploaded as an
  artifact.
- **Fixture:** `fixtures/secrets/` - a made-up AWS access key ID, a
  GitHub-style token with an invalid checksum, a random generic API key, and a
  PEM-shaped block whose body is plain text. None was ever issued by a
  provider.
- **Blind spots / honest notes:**
  - Pattern + entropy matching only. Secrets in formats the default rules
    don't know, low-entropy passwords, or split/encoded values pass.
  - Only this repository's history and tree. Secrets in CI variables, issue
    comments, other repos, container images or logs are out of scope.
  - Detection is after the fact: a secret found in history has already been
    pushed and must be rotated; removing it from the tree does not un-leak it.
  - The volume check parses Gitleaks' log text; a future log-format change
    would make the gate ERROR (fail closed), not pass.
  - Secrets findings cannot be waived by design. A genuine false positive
    needs a reviewed change to the scanned repo's `.gitleaks.toml` (in this
    repo, its unit test pins the allowlist to `fixtures/`).
  - Reused from another repository, the gate uses that repository's own
    `.gitleaks.toml`, or default rules with no allowlist - never ShipSafe's.

### 4. Dockerfile lint - hadolint + ShipSafe policy (implemented, Batch 4)

- **Tool:** hadolint 2.14.0 (GPL-3.0), installed by
  `scripts/install_hadolint.sh` with the version and per-platform SHA-256
  pinned in the repo. The hashes come from the release's per-asset `.sha256`
  files; the linux-x86_64 binary was also byte-identical to `/bin/hadolint` in
  the official `hadolint/hadolint:v2.14.0` image. 2.15.1 exists but publishes
  no checksum files that could be verified from the build environment, so it
  was not pinned (pinning a self-computed hash would be trust-on-first-use).
- **Target:** every file named `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`
  or `Containerfile` under the repo root, excluding `fixtures/` (and `.git`,
  `.venv*`, `.tools`). `--forbid-path fixtures/` makes the gate ERROR if a
  fixture is selected anyway. Today that is one file, `demo-app/Dockerfile`.
- **Fails on:** any hadolint finding at `warning` or `error` (matching
  `failure-threshold: warning` in `.hadolint.yaml`); `info`/`style` are
  reported only. Plus four ShipSafe policy checks, all failing:

  | Check | Catches | Why hadolint alone is not enough |
  |-------|---------|----------------------------------|
  | SS001 | `FROM` without `@sha256:` digest (except `scratch` and stage names) | DL3006/DL3007 only catch untagged/`latest`; a tag can be re-pointed |
  | SS002 | final stage with no `USER`, or last `USER` root/0 | DL3002 only fires when `USER root` is written explicitly |
  | SS003 | `ADD` with an `http(s)://`/`ftp://` source | no hadolint rule for unverified remote ADD |
  | SS004 | `ARG`/`ENV` named like a secret (password, token, secret, api key, private/access key, credential) | build args and ENV persist in image metadata/history |

- **Errors on (fails closed):** no Dockerfiles selected, missing file or
  config, hadolint non-zero exit (it runs with `--no-fail`) or invalid JSON,
  a `DL1000` parse failure, a file with no `FROM` (hadolint returns no
  findings for an empty file), a forbidden path selected.
- **Suppression:** inline `# hadolint ignore=` pragmas are disabled
  (`--disable-ignore-pragma`), `HADOLINT_*` env vars are stripped (hadolint
  reads threshold/ignore settings from them), and `.hadolint.yaml` may only set
  the threshold - a unit test fails if it gains `ignored`, `override` or
  `trustedRegistries`.
- **Demo Dockerfile:** `python:3.13.18-slim-trixie@sha256:e48f59cd...`
  (multi-arch index digest), deps from the fully pinned `requirements.txt`
  with `--no-cache-dir`, a system user/group with uid/gid 10001, `USER
  10001:10001`, exec-form `CMD` and `HEALTHCHECK`, `.dockerignore` limiting
  the context to `requirements.txt` and `app/`. `scripts/verify_demo_image.sh`
  (CI job `demo-image`) builds it and checks the runtime uid, the healthcheck,
  the API and the image history.
- **Fixture:** `fixtures/dockerfile/Dockerfile.vulnerable` - `MAINTAINER`,
  `python:latest`, `ENV API_TOKEN=...` (placeholder), `ADD` from a URL on the
  reserved `.invalid` TLD, unpinned `apt-get`/`pip` installs, `cd` in `RUN`,
  `curl | sh` without pipefail, `USER root`, shell-form `CMD`. Never built.
- **Blind spots / honest notes:**
  - Lints the Dockerfile *text*. Vulnerable packages inside the base image or
    installed at build time are out of scope (Batch 5, Trivy).
  - The policy parser is deliberately small: it joins line continuations and
    skips comments, but does not interpret heredoc (`RUN <<EOF`) bodies,
    `# escape=` directives, or variables in `FROM`/`USER` (`FROM $BASE`
    counts as unpinned; `USER $APP_USER` counts as non-root).
  - SS004 is name-based: a secret passed under an innocuous name, or written
    into a file during `RUN`, is not detected (Gitleaks scans the repo, not
    built images).
  - A digest pin freezes the base image, including its future CVEs; it has
    to be bumped deliberately (Dependabot/Renovate is planned, Batch 6).
  - `pip install` in the image uses version pins but not hashes yet.

### 5. Container image scan - Trivy (implemented, Batch 5)

- **Tool:** Trivy 0.76.2 (Apache-2.0) release binary, installed by
  `scripts/install_trivy.sh` with version and per-platform tarball SHA-256
  pinned in the repo.
- **Supply-chain caveat:** Trivy's own distribution was compromised in March
  2026 (CVE-2026-33634 / GHSA-69fq-xp46-6x23): a malicious v0.69.4 release
  binary, malicious v0.69.5/v0.69.6 images, and force-pushed tags on
  `trivy-action` and `setup-trivy`. ShipSafe therefore never uses those
  actions or any Trivy image, pins a release published long after the
  incident, and pins the hash in-repo. The pinned linux-64bit binary is
  byte-identical to the binary in both the Docker Hub and GHCR 0.76.2 images
  (three independent channels agree). The release's Sigstore signature was
  **not** verified when pinning (no cosign available in the pinning
  environment) - that is a tracked follow-up.
- **Two scans in the gate** (`scripts/container_scan.py`, workflow
  `container-scan.yml`, which builds `demo-app/` first):
  - **image** - `trivy image --scanners vuln --image-config-scanners
    misconfig,secret`: OS packages, language packages, and the image config
    (USER, ENV, HEALTHCHECK, history).
  - **config** - `trivy config` on the repo with `fixtures/` skipped and
    forbidden: Dockerfile (and any future IaC) misconfiguration checks.
    Overlaps hadolint deliberately; the rule sets differ.
- **Fails on:** HIGH/CRITICAL vulnerabilities that have a `FixedVersion`; any
  misconfiguration with status FAIL (any severity); any secret in the image
  config; an OS past end of support (EOSL).
- **Reported, does not fail (default):** vulnerabilities with no fix yet (at
  any severity) and LOW/MEDIUM/UNKNOWN ones. This is ShipSafe's chosen
  default (a red build should point at something fixable in that change); it
  is for the repository owner to review and is not a judgement that those
  findings are acceptable. See "Policy defaults".
- **Errors on (fails closed):** Trivy non-zero exit (it runs with
  `--exit-code 0`), missing/invalid report, report for a different artifact,
  image OS not detected (OS packages not assessed), vulnerability DB older
  than 72 h, config scan that found no files, a forbidden path scanned, or a
  scanned file containing an inline `trivy:ignore` comment.
- **Suppression bypasses closed (all verified while building this):**
  - a `.trivyignore` in the working directory suppresses findings - the gate
    passes `--ignorefile ""`;
  - a `trivy.yaml` in the working directory can change the severity filter
    (one test dropped every finding) - the gate passes `--config ""`;
  - `TRIVY_*` env vars (e.g. `TRIVY_SEVERITY`) do the same - they are
    stripped;
  - inline `# trivy:ignore:<ID>` comments in Dockerfiles suppress findings and
    Trivy has no switch to disable them - the gate ERRORs on any scanned file
    containing one.
- **Demo image changes this batch required** (the first scan failed, which
  is the gate working): the pinned base lacked Debian's `zlib1g` security
  fix, and pip's vendored `urllib3`/`msgpack`/`setuptools` had fixable HIGH
  advisories. The Dockerfile now runs `apt-get update --error-on=any &&
  apt-get upgrade` (an unreachable mirror fails the build; plain `apt-get
  update` exits 0 and silently skips the updates) and uninstalls pip after
  installing the app's dependencies.
- **Fixtures:** `fixtures/container-scan/old-base-image.txt` - a
  digest-pinned `python:3.11.4-slim-bookworm` (Debian 12.1, 2023) scanned with
  `--image-src remote`, so Trivy reads layers from the registry and no
  container is ever created; `Dockerfile.misconfig` for the config scan.
- **Time-variance (important):**
  - The verdict depends on the Trivy DB on the day of the run. A new advisory,
    or a new *fix* for an existing one, can turn an unchanged commit red. That
    is intended - it is when you need to know - but it means CI is not
    reproducible day to day, and a green run says nothing about tomorrow.
  - The usual remedy for a time-variant red is to rebuild (picking up distro
    updates) or bump the base image digest, not to suppress.
  - The self-test never asserts exact counts for the old image, only that
    fixable HIGH/CRITICAL findings exist.
  - Stale data is refused (DB > 72 h = ERROR) rather than trusted.
  - As of the Batch 5 run the demo image showed 0 fixable HIGH/CRITICAL and
    47 HIGH with no fix yet (reported, not failing).
- **Blind spots / honest notes:**
  - Only packages Trivy can identify (distro package DBs, language
    lockfiles/metadata). Binaries copied in by hand, statically linked code,
    or vendored source without metadata are invisible.
  - "No fix available" findings are real exposure. The default policy reports
    them rather than failing on them; that is a default for the owner to
    review, not a decision that they are acceptable - and it does not make
    them go away.
  - Misconfiguration checks are generic best practices; they say nothing
    about the app's own runtime configuration.
  - The DB and checks bundle are fetched at scan time from mirror.gcr.io; the
    gate trusts that channel (it is not hash-pinned, by nature).

## Supply-chain hygiene for the pipeline itself

- Third-party actions pinned to full commit SHAs (unit-tested for every
  workflow, including the consumer example).
- Downloaded binaries (Gitleaks, hadolint, Trivy) pinned by version and
  per-platform SHA-256 in their install scripts, not trusted from a checksums
  file fetched alongside them.
- **Every pip install is hash-pinned** (`--require-hashes`): CI, local setup
  and the demo image install from `pip-compile --generate-hashes` locks
  compiled from `.in` files. A package whose bytes differ from the lock is
  rejected (tested by tampering with a hash). The locks were compiled for
  CPython 3.13 on Linux.
- The demo image's base is pinned by digest.
- **Updates:** Dependabot (`.github/dependabot.yml`) proposes weekly PRs for
  action SHAs, the pip locks and the base-image digest, each with a 7-day
  cooldown after release (fresh releases are the riskiest - see the Trivy
  incident). The binary pins cannot be updated by Dependabot;
  `scripts/check_binary_pins.sh` (weekly `pin-freshness` workflow) reports
  newer upstream releases, and bumping them stays a manual, reviewed change.
- Least-privilege `permissions:`; `persist-credentials: false` on every
  checkout (unit-tested).
- These reduce risk; they do not eliminate it. Hashes prove the bytes are the
  ones that were locked, not that they are benign; the Trivy and GitHub
  Actions downloads still trust their publishers at pinning time.
- **Code-scanning (SARIF) upload is not used.** It is free for public
  repositories but needs GitHub Advanced Security for private ones. A public
  fork could add SARIF output plus a SHA-pinned
  `github/codeql-action/upload-sarif` step (with `security-events: write` on
  that job only); the pass/fail verdict would still come from the gate
  scripts.

## Reuse

All five gate workflows can be called from other repositories - see
[REUSE.md](REUSE.md) and [examples/consumer-security-gates.yml](examples/consumer-security-gates.yml).

- Each workflow checks out ShipSafe separately at `tooling-ref` and moves it to
  `$RUNNER_TEMP` before scanning, so the caller's workspace contains only the
  caller's code. Scripts, install scripts, pins and Semgrep rules come from
  the tooling commit; code, lock files, Dockerfiles, `.gitleaks.toml` and
  `.shipsafe/waivers.yml` come from the caller.
- A caller from another repository must pass a full 40-character commit SHA;
  branches, tags and short SHAs fail the first step (the validation script
  itself is unit-tested).
- Limitation: GitHub does not tell a called workflow which `@ref` its caller
  used, so ShipSafe cannot verify that `tooling-ref` equals the `uses:` SHA.
- Limitation: while ShipSafe is private, callers need the Actions access
  setting and a read-only `tooling-token`.
- `scripts/verify_reuse.sh` (CI `reuse-self-test`) runs every gate from a
  separate tooling copy against a throwaway consumer repository.
