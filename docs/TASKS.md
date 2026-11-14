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

## Batch 3 - Secrets gate (Gitleaks)  `[ ]`

- [ ] Pin Gitleaks binary by version + checksum (free OSS CLI, not the paid action)
- [ ] `.gitleaks.toml` with explicit `fixtures/` allowlist for the app scan
- [ ] `fixtures/secrets/` with clearly fake, non-functional tokens matching default rules
- [ ] `scripts/secrets_scan.sh|py`, reusable `secrets.yml`, self-test

## Batch 4 - Dockerfile lint (hadolint)  `[ ]`

- [ ] `demo-app/Dockerfile` (slim pinned base, non-root user, no build secrets)
- [ ] hadolint pinned; threshold `warning`
- [ ] `fixtures/dockerfile/Dockerfile.vulnerable` (latest tag, root, `ADD` URL, ...)
- [ ] Reusable `dockerfile-lint.yml`, self-test

## Batch 5 - Container scan (Trivy)  `[ ]`

- [ ] Build demo image in CI; Trivy pinned by version + checksum
- [ ] Fail on HIGH/CRITICAL vulns with available fixes; config/misconfig scan
- [ ] Fixture: old base image reference / vulnerable image config
- [ ] Reusable `container-scan.yml`, self-test; document advisory time-variance

## Batch 6 - Hardening and reuse  `[ ]`

- [ ] Waiver mechanism (`.shipsafe/waivers.yml`: id, reason, expiry; expired waivers fail)
- [ ] Hash-pin tool installs (`--require-hashes`)
- [ ] Dependency-audit `scripts/requirements-tools.txt` itself (tool supply chain)
- [ ] Decide whether SAST should also scan `tests/` directories (Semgrep skips them by default)
- [ ] Cross-repo reuse: workflows check out ShipSafe scripts at a pinned ref (or composite actions); usage example
- [ ] Optional SARIF upload to GitHub code scanning (free for public repos)
- [ ] Dependabot/Renovate config for action + tool pin updates

## Batch 7 - Docs polish  `[ ]`

- [ ] README walkthrough with real CI run output for pass and fail cases
- [ ] "Limitations" section reviewed against final behaviour of every gate
