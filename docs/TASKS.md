# ShipSafe task plan

Ordered batches. Each batch is a small increment on the session branch, with
its own tests / scripted verification, reviewed by the repo owner before merge.
Status: `[x]` done, `[ ]` not started.

## Batch 0 - Project docs  `[x]`

- [x] `CLAUDE.md` with workflow rules, layout, conventions, run commands
- [x] `docs/DESIGN.md` - architecture, gate design, honest scope notes
- [x] `docs/TASKS.md` - this plan
- [x] Expanded `README.md`

## Batch 1 - Layout + dependency-audit gate  `[x]`

- [x] Repo layout: `.github/workflows/`, `demo-app/`, `fixtures/`, `scripts/`, `docs/`
- [x] Minimal FastAPI demo app with fully pinned deps and pytest tests
- [x] `scripts/dependency_audit.py` (pip-audit wrapper, exit codes 0/1/2, fail-closed)
- [x] `fixtures/dependency-audit/vulnerable-requirements.txt` + `fixtures/README.md`
- [x] Reusable workflow `dependency-audit.yml` + `ci.yml` wiring
- [x] `scripts/verify_dependency_audit.sh` self-test (PASS app / FAIL fixture / ERROR unpinned)
- [x] Offline unit tests in `scripts/tests/`
- Verification: demo-app tests, gate unit tests, self-test script, actionlint+shellcheck

## Batch 2 - SAST gate (Semgrep)  `[x]`

- [x] Pin Semgrep OSS CLI (1.185.0); vendor 10 reviewed Python/FastAPI rules in `rules/semgrep/` (no login/registry)
- [x] Annotated rule tests (`semgrep --test`), one positive + negative case per rule
- [x] `scripts/sast.py` parsing Semgrep JSON; fail on ERROR/WARNING; INFO reported only; fail closed on
      semgrep errors, skipped rules, 0 files scanned, forbidden paths scanned, unparseable Python
- [x] `fixtures/sast/vulnerable_app.py` - `shell=True`/`os.system` with request input, `yaml.load`, `eval`, f-string SQL, `pickle.loads`
- [x] Reusable `sast.yml`; project scan targets repo root with explicit `fixtures/` exclude + forbid guard
- [x] `scripts/verify_sast.sh` + offline unit tests (`scripts/tests/test_sast.py`)
- Verification: rule tests, unit tests, self-test script, actionlint+shellcheck

## Batch 3 - Secrets gate (Gitleaks)  `[x]`

- [x] Pin Gitleaks 8.30.1 by version + per-platform SHA-256 in `scripts/install_gitleaks.sh` (OSS CLI, not the action)
- [x] `.gitleaks.toml`: default rules + a single anchored `fixtures/` path allowlist; unit test pins its shape
- [x] `rules/gitleaks/default-only.toml` for the fixture scan (no allowlist)
- [x] `fixtures/secrets/` - fake AWS key ID, GitHub-style token (bad checksum), generic API key, PEM-shaped block
- [x] `scripts/secrets_scan.py`: dir/git modes, `--redact`, ignores `gitleaks:allow`, ERROR on
      `.gitleaksignore`, 0 bytes/commits scanned, shallow clone, gitleaks failure
- [x] Reusable `secrets.yml` (full-history scan, `fetch-depth: 0`) + CI jobs
- [x] `scripts/verify_secrets.sh` (9 checks) + offline unit tests (`scripts/tests/test_secrets_scan.py`)
- Verification: unit tests, self-test, installer tamper test, actionlint+shellcheck, other gates re-run

## Batch 4 - Dockerfile lint (hadolint)  `[x]`

- [x] `demo-app/Dockerfile`: `python:3.13.18-slim-trixie@sha256:...` base, non-root uid 10001,
      HEALTHCHECK, no ARG/secrets; `.dockerignore` limits context to requirements + app
- [x] hadolint 2.14.0 pinned by version + per-platform SHA-256 (`scripts/install_hadolint.sh`);
      `.hadolint.yaml` = `failure-threshold: warning`, nothing ignored (unit-test enforced)
- [x] ShipSafe policy checks hadolint lacks: SS001 digest pin, SS002 non-root final USER,
      SS003 no ADD from URL, SS004 no secret-named ARG/ENV
- [x] Fail closed: no Dockerfiles, missing file, hadolint error/invalid JSON, DL1000 parse
      failure, no FROM, forbidden path; pragmas + HADOLINT_* env disabled
- [x] `fixtures/dockerfile/Dockerfile.vulnerable` (MAINTAINER, latest, root, ADD URL, secret ENV, ...)
- [x] Reusable `dockerfile-lint.yml` with discovery (fixtures/ excluded + forbidden), CI jobs
- [x] `scripts/verify_dockerfile_lint.sh` (9 checks), unit tests, `scripts/verify_demo_image.sh`
      + `demo-image` CI job (build, uid 10001, healthy, API)
- Verification: unit tests, self-test, installer tamper test, image build/run, actionlint+shellcheck,
  other gates re-run

## Batch 5 - Container scan (Trivy)  `[x]`

- [x] Trivy 0.76.2 pinned by version + per-platform SHA-256 (`scripts/install_trivy.sh`); no
      trivy-action / setup-trivy / Trivy image (March 2026 compromise, CVE-2026-33634); linux binary
      cross-checked against the Docker Hub and GHCR images
- [x] `scripts/container_scan.py`: image mode (vuln + image-config misconfig/secret) and config mode;
      FAIL on fixable HIGH/CRITICAL, any misconfig, secrets, EOL OS; unfixed reported only
- [x] Fail closed: trivy error/no report, wrong artifact, OS not detected, DB > 72h old, nothing
      scanned, forbidden path, inline `trivy:ignore`; trivy.yaml/.trivyignore/TRIVY_* disabled
- [x] Demo image hardened to pass: `apt-get upgrade` (with `--error-on=any`), pip removed after install
- [x] Fixtures: `old-base-image.txt` (scanned remotely, never run) + `Dockerfile.misconfig`
- [x] Reusable `container-scan.yml` (builds image, both scans) + CI jobs; self-test (8 checks); unit tests
- [x] Time-variance documented (DESIGN, README, CLAUDE.md, workflow, script)
- Verification: unit tests, self-test, installer tamper test, real image scan, other gates re-run

## Batch 6 - Hardening and reuse  `[x]`

- [x] Waivers: `.shipsafe/waivers.yml` (id, gate, reason, expires <= 90 days, optional scope),
      shared `scripts/waivers.py`; expired waiver FAILS, invalid file ERRORs; secrets and scan
      errors not waivable; applied in dependency-audit, SAST, Dockerfile and container gates
- [x] `scripts/verify_waivers.sh` + `fixtures/waivers/` + CI `waivers-self-test`; unit tests
- [x] Closed two SAST bypasses found on the way: `# nosemgrep` (now `--disable-nosem`) and
      `.semgrepignore` (now ERROR)
- [x] Hash-pinned pip installs everywhere (`--require-hashes`, pip-compile locks from `.in` files)
- [x] Cross-repo reuse: tooling checkout at a pinned SHA in all five reusable workflows, moved out
      of the workspace; secrets config defaults to the caller's own (never ShipSafe's allowlist);
      `docs/REUSE.md`, `docs/examples/consumer-security-gates.yml`, `scripts/verify_reuse.sh` +
      CI `reuse-self-test`
- [x] Dependabot for actions, pip locks and the base-image digest (7-day cooldown);
      `scripts/check_binary_pins.sh` + weekly `pin-freshness` report for binary pins
- [x] Severity thresholds documented as reviewable project defaults ("Policy defaults")
- [ ] ~~SARIF upload~~ - not used (private repo; paid feature there); documented as an option for
      public repos in DESIGN.md / REUSE.md

### Original Batch 6 list (for reference)


- [x] Waiver mechanism (`.shipsafe/waivers.yml`: id, reason, expiry; expired waivers fail)
- [x] Hash-pin tool installs (`--require-hashes`)
- [ ] Dependency-audit `scripts/requirements-tools.txt` itself (tool supply chain)
- [ ] Decide whether SAST should also scan `tests/` directories (Semgrep skips them by default)
- [ ] Secrets: decide on a reviewed waiver path for real false positives (today: widen `.gitleaks.toml` + its test)
- [ ] hadolint: move to 2.15.x once its checksums can be verified against an upstream-published source
- [x] Demo image: install deps with `pip --require-hashes` (Batch 6)
- [ ] Dockerfile policy parser: interpret heredoc (`RUN <<EOF`) bodies; today they are not inspected
- [ ] Trivy: verify the release's Sigstore bundle (cosign) when bumping the pin - not done for 0.76.2
- [ ] Container scan: cache the Trivy DB between CI runs; consider a scheduled (nightly) run so
      time-variant failures surface without a commit
- [ ] Decide whether the default severity thresholds fit this project (owner review; see
      DESIGN.md "Policy defaults")
- [ ] Waivers: consider requiring a named approver field once more than one person maintains this
- [x] Cross-repo reuse: workflows check out ShipSafe scripts at a pinned ref; usage example
- [ ] Optional SARIF upload to GitHub code scanning (free for public repos) - documented only
- [x] Dependabot config for action + tool pin updates (+ binary pin freshness report)

## Batch 7 - Docs polish  `[ ]`

- [ ] README walkthrough with real CI run output for pass and fail cases
- [ ] "Limitations" section reviewed against final behaviour of every gate
