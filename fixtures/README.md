# fixtures/ - DELIBERATELY VULNERABLE SAMPLES

**Do not use anything in this directory in real software. Do not deploy it,
install it, or point it at any real system.**

Every file here exists only to prove that a ShipSafe CI gate *fails* when it
sees a real, known issue. Each gate has a self-test that runs the gate against
its fixture and asserts that the gate reports failure. If a gate ever passes on
its fixture, the self-test fails and CI goes red.

Rules for fixtures:

- Fixtures are inert data. They are scanned, never installed or executed.
- Each fixture documents what it seeds and which finding(s) the gate is
  expected to report.
- Production gates must never scan `fixtures/`. Each scanner excludes it
  explicitly for the project scan (SAST also passes `--forbid-path fixtures/`
  so a broken exclude makes the gate error; the secrets gate allowlists
  exactly `^(\./)?fixtures/` in `.gitleaks.toml`, and its self-test proves
  that nothing outside `fixtures/` is hidden; the Dockerfile gate excludes
  `fixtures/` from discovery and passes `--forbid-path fixtures/`; the
  Trivy config scan uses `--skip-dir fixtures --forbid-path fixtures/`).

| Path | Gate | Seeded issue |
|------|------|--------------|
| `dependency-audit/vulnerable-requirements.txt` | dependency audit (pip-audit) | Old pins with published advisories |
| `secrets/fake-credentials.env`, `fake_settings.py`, `fake_private_key.pem` | secrets (Gitleaks) | Made-up, never-issued AWS key ID, GitHub-style token (invalid checksum), generic API key, and a PEM-shaped block with a plain-text body. They match Gitleaks default rules and authenticate against nothing. |
| `dockerfile/Dockerfile.vulnerable` | Dockerfile lint (hadolint + policy) | `MAINTAINER`, `python:latest` (no digest), secret-named `ENV`, `ADD` from a URL on the reserved `.invalid` TLD, unpinned apt/pip installs, `cd` in RUN, `curl \| sh` without pipefail, `USER root`, shell-form `CMD`. Never built. |
| `container-scan/old-base-image.txt` | container scan (Trivy image) | Digest-pinned reference to `python:3.11.4-slim-bookworm` (Debian 12.1, 2023): many fixable HIGH/CRITICAL vulns, runs as root, no HEALTHCHECK. Read from the registry with `--image-src remote`; never pulled into Docker, never run. |
| `container-scan/Dockerfile.misconfig` | container scan (Trivy config) | `debian:latest`, apt without `--no-install-recommends`, `ADD` from a `.invalid` URL, `USER root`, no HEALTHCHECK. Never built. |
| `sast/vulnerable_app.py` | SAST (Semgrep) | FastAPI handlers with command injection (`shell=True`, `os.system`), `yaml.load`, `eval`, f-string SQL, `pickle.loads`. Raises on import. |

`rules/semgrep/python-security.py` (outside this directory) is also
deliberately vulnerable: it holds the annotated test cases for the vendored
Semgrep rules and is likewise excluded from the project scan.
