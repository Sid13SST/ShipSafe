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
  ci.yml                  # entry pipeline: tests, gates on demo-app, gate self-tests
  dependency-audit.yml    # reusable gate (workflow_call): pip-audit
demo-app/                 # minimal FastAPI app - the "clean" target; gates must PASS
  app/main.py
  requirements.txt        # runtime deps, fully pinned incl. transitive (lockfile)
  requirements-dev.txt    # test deps, fully pinned
  tests/
fixtures/                 # DELIBERATELY VULNERABLE samples - gates must FAIL; never install/run
  README.md               # index of what each fixture seeds
  dependency-audit/vulnerable-requirements.txt
scripts/
  dependency_audit.py     # gate logic shared by CI and local runs
  verify_dependency_audit.sh  # self-test: PASS on app, FAIL on fixture, ERROR on unpinned
  requirements-tools.txt  # pinned versions of gate tools
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
- Workflows use `permissions: contents: read` and
  `persist-credentials: false` unless a gate needs more (document why).
- Python 3.13, stdlib-only for gate scripts where practical.

## Running locally

Set up a venv once (any location):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r scripts/requirements-tools.txt -r demo-app/requirements.txt -r demo-app/requirements-dev.txt
```

| What | Command |
|------|---------|
| Demo-app tests | `cd demo-app && python -m pytest -q` |
| Gate unit tests (offline) | `python -m pytest -q scripts/tests` |
| Dependency-audit gate on the app | `python scripts/dependency_audit.py demo-app/requirements.txt demo-app/requirements-dev.txt` |
| Dependency-audit self-test | `bash scripts/verify_dependency_audit.sh` |
| Run the demo app | `cd demo-app && uvicorn app.main:app --reload` |
| Lint workflows (optional) | `pip install actionlint-py shellcheck-py && actionlint` |

The pip-audit steps need network access to PyPI's vulnerability data.

## CI

`ci.yml` runs on every push, pull request, and manual dispatch:

| Job | Must | Meaning |
|-----|------|---------|
| `demo-app-tests` | pass | app works |
| `gate-unit-tests` | pass | gate parsing/exit-code logic is correct |
| `dependency-audit` | pass | no known advisory matched demo-app pins (the real gate) |
| `dependency-audit-self-test` | pass | gate PASSes clean app, FAILs the fixture, ERRORs on unpinned input |

## Updating demo-app pins

Install the top-level deps in a fresh venv and freeze:

```bash
python3 -m venv /tmp/lock && /tmp/lock/bin/pip install fastapi==<ver> uvicorn==<ver>
/tmp/lock/bin/pip freeze   # paste into demo-app/requirements.txt below the header
```

Then rerun the demo-app tests and `scripts/verify_dependency_audit.sh`.

## Status

Batch 0 (docs) and Batch 1 (layout + dependency-audit gate) are done. See
`docs/TASKS.md` for what comes next.
