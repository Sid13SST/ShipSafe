# ShipSafe

DevSecOps CI template: automated security checks (dependency audit, SAST,
secrets, container scanning) run as **pass/fail gates** in GitHub Actions, with
a minimal demo app and seeded vulnerable fixtures that prove the gates catch
real issues.

> **Scope, honestly:** these are automated checks in CI, not a security
> guarantee. Which findings fail a build and which are only reported is a
> project default for the repository owner to review (see
> [docs/DESIGN.md](docs/DESIGN.md#policy-defaults-for-the-repository-owner-to-review)),
> not a judgement that anything reported-only is acceptable. A passing pipeline means the configured open-source tools, with
> their current rules and advisory data, reported nothing above the fail
> thresholds at run time. Findings below a threshold are still reported but do
> not fail the build. It does
> not mean the code or its dependencies are secure.

## Gates

| Gate | Tool | Status |
|------|------|--------|
| Dependency vulnerability audit | [pip-audit](https://github.com/pypa/pip-audit) | Implemented |
| SAST | [Semgrep](https://github.com/semgrep/semgrep) OSS CLI, vendored rules, offline | Implemented |
| Secrets detection | [Gitleaks](https://github.com/gitleaks/gitleaks) OSS CLI, pinned + checksum-verified binary | Implemented |
| Dockerfile lint | [hadolint](https://github.com/hadolint/hadolint), pinned + checksum-verified binary, plus 4 ShipSafe policy checks | Implemented |
| Container image scan | [Trivy](https://github.com/aquasecurity/trivy), pinned + checksum-verified release binary (no Trivy actions/images) | Implemented |

All tooling is free and open source.

## How a gate proves itself

Each gate runs twice in CI:

1. **On the demo app** (`demo-app/`) - must **pass**. This is the real gate.
2. **On its fixture** (`fixtures/<gate>/`) - must **fail** with the expected
   findings. A self-test script asserts this, so a gate that silently stops
   catching issues turns CI red.

Gates fail closed: if a tool cannot complete the audit, the gate reports
`ERROR` and fails rather than passing.

**Exceptions** for individual findings go in `.shipsafe/waivers.yml`: each
needs a reason and an expiry at most 90 days out, an expired waiver fails
the build, and secrets can never be waived. Inline suppression comments and
tool ignore files are not honoured.

**Pinned supply chain:** actions by commit SHA, pip packages by hash
(`--require-hashes`), downloaded binaries by SHA-256, the base image by
digest. Dependabot proposes updates after a 7-day cooldown.

**Reuse:** the gate workflows can be called from other repositories at a
pinned ShipSafe commit - see [docs/REUSE.md](docs/REUSE.md).

## Repository layout

```
.github/workflows/   CI entry (ci.yml) and reusable gate workflows
demo-app/            minimal FastAPI app (the clean target)
fixtures/            DELIBERATELY VULNERABLE samples - never install or run
rules/semgrep/       vendored, reviewed Semgrep rules + their annotated tests
rules/gitleaks/      default-rules-only config used by the secrets self-test
.gitleaks.toml       project secrets config (default rules + fixtures/ allowlist only)
.shipsafe/           waivers.yml - time-boxed, reviewed exceptions (empty)
.hadolint.yaml       hadolint config (fail at warning, nothing ignored)
scripts/             gate logic + self-test scripts (same code in CI and locally)
docs/                DESIGN.md (architecture, policy, scope), REUSE.md, examples/, TASKS.md
```

## Quick start (local)

```bash
python3 -m venv .venv-tools && .venv-tools/bin/pip install --require-hashes -r scripts/requirements-tools.txt -r demo-app/requirements-dev.txt
```

```bash
bash scripts/install_gitleaks.sh .tools/bin && bash scripts/install_hadolint.sh .tools/bin && bash scripts/install_trivy.sh .tools/bin && export PATH="$PWD/.tools/bin:$PATH"
```

```bash
. .venv-tools/bin/activate && bash scripts/verify_dependency_audit.sh && bash scripts/verify_sast.sh && bash scripts/verify_secrets.sh && bash scripts/verify_dockerfile_lint.sh && bash scripts/verify_container_scan.sh && bash scripts/verify_waivers.sh && bash scripts/verify_reuse.sh
```

> **Results change over time.** The dependency audit and container scan
> compare against advisory databases that are updated daily. A commit that
> was green yesterday can turn red today because a new vulnerability - or a
> new fix for an old one - was published. That is the intended behaviour; it
> also means a green run is a statement about that day's data only.

The demo app uses its own venv (`.venv`); see [CLAUDE.md](CLAUDE.md).

More commands, conventions, and CI job descriptions: [CLAUDE.md](CLAUDE.md).
Design and per-gate limitations: [docs/DESIGN.md](docs/DESIGN.md).

## About `fixtures/`

Everything under `fixtures/` is intentionally vulnerable and exists only to be
scanned. See [fixtures/README.md](fixtures/README.md).


## Limitations at a glance

Short version. Per-gate detail, blind spots and the policy defaults are in
[docs/DESIGN.md](docs/DESIGN.md).

- A green run means no gate crossed its configured fail threshold. It does not
  mean nothing was found. Findings below a threshold are reported but do not
  fail the build. Example: the demo image scan passes while reporting 47 HIGH
  vulnerabilities that have no fix yet, because the container gate only fails by
  default on HIGH/CRITICAL vulnerabilities that have a fixed version. It is not a
  security guarantee, and it does not mean the code or image is free of known
  vulnerabilities.
- Which findings fail the build and which are only reported is a project default
  for the repository owner to review. It has not been accepted as a risk decision.
- Dependency audit and container scan results change over time as new advisories
  are published, so the same commit can pass today and fail later.
- SAST (Semgrep, vendored offline rules) and Dockerfile lint cover only the rules
  and patterns they ship with. Many bug classes are not detected.
- Secrets detection finds known patterns and high-entropy strings. It can miss
  secrets and can flag harmless strings.
- Waivers are time-limited and are the owner's decision. An expired waiver stops
  suppressing the finding.
- The seeded fixtures show that each gate catches its own known cases. They do not
  show that the gates catch issues in other code.
- Reuse from other repositories is pinned to a commit SHA. While ShipSafe is
  private, callers need Actions access to this repository.
## Walkthrough: what a pass and a fail look like

Real output from CI run #6 (commit b376db4). Fail cases come from the seeded
fixtures and are expected to fail; the self-test jobs check that they do.

Pass, on the demo app and image (these fail only on the thresholds in
[docs/DESIGN.md](docs/DESIGN.md#policy-defaults-for-the-repository-owner-to-review)):

```text
container-scan [image shipsafe-demo:ci]: PASS - OS debian 13.7, 3 target(s); failing: none
  informational (does not fail): 47 HIGH no fix yet, 65 LOW no fix yet, 89 MEDIUM no fix yet, 5 UNKNOWN no fix yet
sast [.]: PASS - 8 file(s) scanned, 0 failing finding(s), 0 informational
```

The first line is a pass that still reports 47 HIGH vulnerabilities with no fix
available yet. They are listed, not hidden, and a pass does not mean they are
acceptable.

Fail, on a seeded vulnerable fixture, caught as expected:

```text
sast [fixtures/sast]: FAIL - 1 file(s) scanned, 8 failing finding(s), 0 informational
  - fixtures/sast/vulnerable_app.py:45 [ERROR] shipsafe.yaml-unsafe-load
  - fixtures/sast/vulnerable_app.py:51 [ERROR] shipsafe.eval-exec-non-literal
SELF-TEST OK   [vulnerable fixture]: exit 1 as expected
container-scan [config fixtures/container-scan]: FAIL, 1 target(s); failing: 4 misconfig
  - [misconfig] DS-0002 HIGH Image user should not be 'root' (Dockerfile.misconfig)
SELF-TEST OK   [config scan, fixture]: exit 1 as expected
```

These show that each gate catches its own known cases. They say nothing about
code outside the fixtures.
