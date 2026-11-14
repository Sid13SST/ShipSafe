# ShipSafe

DevSecOps CI template: automated security checks (dependency audit, SAST,
secrets, container scanning) run as **pass/fail gates** in GitHub Actions, with
a minimal demo app and seeded vulnerable fixtures that prove the gates catch
real issues.

> **Scope, honestly:** these are automated checks in CI, not a security
> guarantee. A passing pipeline means the configured open-source tools, with
> their current rules and advisory data, reported nothing at run time. It does
> not mean the code or its dependencies are secure.

## Gates

| Gate | Tool | Status |
|------|------|--------|
| Dependency vulnerability audit | [pip-audit](https://github.com/pypa/pip-audit) | Implemented |
| SAST | [Semgrep](https://github.com/semgrep/semgrep) (OSS) | Planned |
| Secrets detection | [Gitleaks](https://github.com/gitleaks/gitleaks) | Planned |
| Dockerfile lint | [hadolint](https://github.com/hadolint/hadolint) | Planned |
| Container image scan | [Trivy](https://github.com/aquasecurity/trivy) | Planned |

All tooling is free and open source.

## How a gate proves itself

Each gate runs twice in CI:

1. **On the demo app** (`demo-app/`) - must **pass**. This is the real gate.
2. **On its fixture** (`fixtures/<gate>/`) - must **fail** with the expected
   findings. A self-test script asserts this, so a gate that silently stops
   catching issues turns CI red.

Gates fail closed: if a tool cannot complete the audit, the gate reports
`ERROR` and fails rather than passing.

## Repository layout

```
.github/workflows/   CI entry (ci.yml) and reusable gate workflows
demo-app/            minimal FastAPI app (the clean target)
fixtures/            DELIBERATELY VULNERABLE samples - never install or run
scripts/             gate logic + self-test scripts (same code in CI and locally)
docs/                DESIGN.md (architecture, scope), TASKS.md (build plan)
```

## Quick start (local)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r scripts/requirements-tools.txt -r demo-app/requirements.txt -r demo-app/requirements-dev.txt
```

```bash
bash scripts/verify_dependency_audit.sh
```

```bash
cd demo-app && python -m pytest -q
```

More commands, conventions, and CI job descriptions: [CLAUDE.md](CLAUDE.md).
Design and per-gate limitations: [docs/DESIGN.md](docs/DESIGN.md).

## About `fixtures/`

Everything under `fixtures/` is intentionally vulnerable and exists only to be
scanned. See [fixtures/README.md](fixtures/README.md).
