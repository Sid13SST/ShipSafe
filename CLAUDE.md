# CLAUDE.md - ShipSafe working agreement

ShipSafe is a DevSecOps CI template: a GitHub Actions pipeline that runs
automated security checks as real pass/fail gates, a minimal FastAPI demo app
the gates must pass on, and a clearly marked `fixtures/` directory of
deliberately vulnerable samples the gates must fail on.

**Framing rule:** everything here is *automated checks in CI*, not a security
guarantee. A green pipeline means "these tools, with these rules and this
advisory data, found nothing at run time". Keep that wording in code, docs,
workflow names, and commit messages.

## Workflow rules (apply to all work in this repo)

1. **Context.** This file documents architecture, conventions, and how to run
   everything locally and in CI. Update it in the same increment as any change
   that makes it stale.
2. **Small tasks.** Work in small, self-contained increments on the session
   branch. Never commit to `main` directly. Do not merge anything and do not
   open PRs marked ready for merge - the repo owner reviews and approves merges.
3. **Tests.** Every increment ships with tests or a scripted verification that
   proves it works. Run them and report the actual output.
4. **Tools.** Free, open-source tooling only.
5. **Git.** Before the first commit in a clone run:
   ```bash
   git config user.name Sid13SST
   git config user.email 220563227+Sid13SST@users.noreply.github.com
   ```
   Every commit is authored only by that identity. No Claude / `Co-Authored-By`
   trailers, no history rewrites, no empty or padding commits.

## Layout

```
.github/workflows/
  ci.yml                  # entry pipeline: tests, gates on the project, gate self-tests
  dependency-audit.yml    # reusable gate (workflow_call): pip-audit
  sast.yml                # reusable gate (workflow_call): Semgrep OSS, vendored rules
  secrets.yml             # reusable gate (workflow_call): Gitleaks, pinned binary
  dockerfile-lint.yml     # reusable gate (workflow_call): hadolint, pinned binary, + policy checks
.gitleaks.toml            # project secrets config: default rules + fixtures/ path allowlist ONLY
.hadolint.yaml            # hadolint config: failure-threshold warning, nothing ignored
demo-app/                 # minimal FastAPI app - the "clean" target; gates must PASS
  app/main.py
  Dockerfile              # pinned-digest slim base, non-root uid 10001, healthcheck, no build secrets
  .dockerignore           # context = requirements.txt + app/ only
  requirements.txt        # runtime deps, fully pinned incl. transitive (lockfile)
  requirements-dev.txt    # test deps, fully pinned
  tests/
fixtures/                 # DELIBERATELY VULNERABLE samples - gates must FAIL; never install/run
  README.md               # index of what each fixture seeds
  dependency-audit/vulnerable-requirements.txt
  sast/vulnerable_app.py  # raises on import; scanned only
  secrets/                # fake, non-functional tokens matching Gitleaks default rules
  dockerfile/Dockerfile.vulnerable  # latest tag, root, ADD from .invalid URL, ...; never built
rules/semgrep/
  python-security.yml     # vendored, reviewed Semgrep rules (offline, no registry)
  python-security.py      # annotated rule tests for `semgrep --test` (also deliberately vulnerable)
rules/gitleaks/
  default-only.toml       # default rules, no allowlist - self-test only (fixture scan)
scripts/
  dependency_audit.py     # gate logic shared by CI and local runs
  verify_dependency_audit.sh  # self-test: PASS on app, FAIL on fixture, ERROR on unpinned
  sast.py                 # Semgrep gate logic shared by CI and local runs
  verify_sast.sh          # self-test: rule tests, PASS on project, FAIL on fixture, guards
  secrets_scan.py         # Gitleaks gate logic shared by CI and local runs
  install_gitleaks.sh     # installs pinned Gitleaks release, SHA-256 verified
  verify_secrets.sh       # self-test: PASS on project (tree + history), FAIL on fixture, guards
  dockerfile_lint.py      # Dockerfile gate: hadolint + ShipSafe policy checks SS001-SS004
  install_hadolint.sh     # installs pinned hadolint release, SHA-256 verified
  verify_dockerfile_lint.sh  # self-test: PASS on project, FAIL on fixture, guards
  verify_demo_image.sh    # builds demo image; checks uid 10001, healthy, API, no secret ARG/ENV
  requirements-tools.txt  # pinned versions of gate tools (own venv - see below)
  tests/                  # offline unit tests for gate scripts
docs/
  DESIGN.md               # architecture, gate design, honest scope notes
  TASKS.md                # ordered batch plan and status
```

## Conventions

- **One gate = one reusable workflow + one script + one fixture + one self-test.**
  Gate logic lives in `scripts/` so CI and local runs give the same verdict;
  workflows stay thin.
- **Gate exit codes:** `0` PASS, `1` FAIL (findings), `2` ERROR (could not
  audit). Gates fail closed: an audit that did not complete is never a pass.
- **Fixtures are inert.** Scanned only, never installed or executed, never
  pointed at real targets. Every fixture file starts with a
  "DELIBERATELY VULNERABLE" header. App-scanning jobs must not include
  `fixtures/`.
- **Pin everything.** Actions by full commit SHA (with a `# vX.Y.Z` comment),
  tool versions in `scripts/requirements-tools.txt`, demo-app deps fully pinned.
- **Scan the whole project, exclude explicitly.** Gates that scan source take
  the repo root as target and exclude `fixtures/` (and any other deliberately
  vulnerable file, e.g. `rules/semgrep/python-security.py`) by explicit flag,
  plus `--forbid-path fixtures/` so a broken exclude errors instead of
  silently scanning the fixtures.
- **Semgrep runs offline:** local `--config` only, `--metrics=off`,
  `--disable-version-check`, `--oss-only`. Never use `--config auto`/`p/...`
  (registry) or `semgrep --validate` (it fetches lint rules from semgrep.dev).
  New rules need annotated `ruleid`/`ok` cases in `python-security.py`.
- **Secrets: one suppression mechanism.** Only the path allowlist in
  `.gitleaks.toml` may suppress findings, and a unit test pins it to
  `^(\./)?fixtures/`. The gate ignores inline `gitleaks:allow` comments and
  errors if any `.gitleaksignore` exists. Fake tokens built in scripts/tests
  must be assembled from pieces at runtime so the project scan stays green.
  Never print secret values (Gitleaks runs with `--redact`).
- **Binary tools** (Gitleaks, hadolint) are pinned by version *and*
  per-platform SHA-256 inside their install script; a mismatch aborts the
  install. Only pin a release whose checksums upstream publishes.
- **Dockerfiles** must pass hadolint at `warning` and the ShipSafe policy
  checks: base image pinned `image:tag@sha256:...` (SS001), final stage runs
  as a non-root `USER` (SS002), no `ADD` from a URL (SS003), no ARG/ENV with a
  secret-looking name (SS004). hadolint runs with `--disable-ignore-pragma`
  and without `HADOLINT_*` env vars; `.hadolint.yaml` may only set the
  threshold (a unit test enforces it). New Dockerfiles anywhere outside
  `fixtures/` are discovered and linted automatically.
- Workflows use `permissions: contents: read` and
  `persist-credentials: false` unless a gate needs more (document why).
- Python 3.13, stdlib-only for gate scripts where practical.

## Running locally

Use two venvs: Semgrep pins an older `opentelemetry-api` than FastAPI
accepts, so gate tools and the demo app cannot share one environment.

```bash
python3 -m venv .venv-tools && .venv-tools/bin/pip install -r scripts/requirements-tools.txt -r demo-app/requirements-dev.txt
python3 -m venv .venv && .venv/bin/pip install -r demo-app/requirements.txt -r demo-app/requirements-dev.txt
bash scripts/install_gitleaks.sh .tools/bin && bash scripts/install_hadolint.sh .tools/bin
export PATH="$PWD/.tools/bin:$PATH"
```

Run gate commands with `.venv-tools` activated and demo-app commands with
`.venv` activated.

| What | Command |
|------|---------|
| Demo-app tests (`.venv`) | `cd demo-app && python -m pytest -q` |
| Gate unit tests (offline) | `python -m pytest -q scripts/tests` |
| Dependency-audit gate on the app | `python scripts/dependency_audit.py demo-app/requirements.txt demo-app/requirements-dev.txt` |
| Dependency-audit self-test | `bash scripts/verify_dependency_audit.sh` |
| SAST gate on the project | `python scripts/sast.py . --exclude fixtures/ --exclude rules/semgrep/python-security.py --forbid-path fixtures/` |
| SAST rule tests | `semgrep --test --metrics=off rules/semgrep` |
| SAST self-test | `bash scripts/verify_sast.sh` |
| Secrets gate, working tree | `python scripts/secrets_scan.py . --mode dir` |
| Secrets gate, full history (as CI) | `python scripts/secrets_scan.py . --mode git` |
| Secrets self-test | `bash scripts/verify_secrets.sh` |
| Dockerfile gate (as CI) | `python scripts/dockerfile_lint.py --discover . --exclude fixtures/ --forbid-path fixtures/` |
| Dockerfile self-test | `bash scripts/verify_dockerfile_lint.sh` |
| Demo image build + runtime check (needs Docker) | `bash scripts/verify_demo_image.sh demo-app` |
| Run the demo app | `cd demo-app && uvicorn app.main:app --reload` |
| Lint workflows (optional) | `pip install actionlint-py shellcheck-py && actionlint` |

The pip-audit steps need network access to PyPI's vulnerability data.
The install scripts need to reach github.com once. The SAST, secrets and
Dockerfile gates themselves need no network access. `verify_demo_image.sh`
needs Docker plus access to Docker Hub and PyPI. (In a sandbox behind a
TLS-intercepting proxy, build containers don't trust the proxy CA; verify
with a scratch copy of `demo-app/` that adds the CA - never commit that.)

## CI

`ci.yml` runs on every push, pull request, and manual dispatch:

| Job | Must | Meaning |
|-----|------|---------|
| `demo-app-tests` | pass | app works |
| `gate-unit-tests` | pass | gate parsing/exit-code logic is correct |
| `dependency-audit` | pass | no known advisory matched demo-app pins (the real gate) |
| `dependency-audit-self-test` | pass | gate PASSes clean app, FAILs the fixture, ERRORs on unpinned input |
| `sast` | pass | no ERROR/WARNING Semgrep finding in the project (fixtures/ excluded) - the real gate |
| `sast-self-test` | pass | rule tests pass; gate PASSes project, FAILs fixture, ERRORs if fixtures/ is scanned or Python is unparseable, ignores INFO |
| `secrets` | pass | Gitleaks found nothing in the full git history (fixtures/ allowlisted) - the real gate |
| `secrets-self-test` | pass | PASS on tree + history, FAIL on fixture, allowlist hides only fixtures/, ERROR on .gitleaksignore / empty / shallow, inline allow ignored, deleted secret still caught |
| `dockerfile-lint` | pass | every Dockerfile outside fixtures/ passes hadolint (warning+) and SS001-SS004 - the real gate |
| `dockerfile-lint-self-test` | pass | PASS on project, FAIL on fixture (hadolint + all SS rules), ERROR on forbidden/empty/unparseable, pragma + env can't weaken it, missing USER caught, info doesn't fail |
| `demo-image` | pass | committed demo-app/Dockerfile builds; container runs as uid 10001, becomes healthy, serves the API |

## Updating demo-app pins

Install the top-level deps in a fresh venv and freeze:

```bash
python3 -m venv /tmp/lock && /tmp/lock/bin/pip install fastapi==<ver> uvicorn==<ver>
/tmp/lock/bin/pip freeze   # paste into demo-app/requirements.txt below the header
```

Then rerun the demo-app tests and `scripts/verify_dependency_audit.sh`.

## Status

Batch 0 (docs), Batch 1 (layout + dependency-audit gate), Batch 2
(SAST gate), Batch 3 (secrets gate) and Batch 4 (Dockerfile gate) are
done. See
`docs/TASKS.md` for what comes next.
