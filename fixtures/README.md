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
  so a broken exclude makes the gate error). Later scanners (Gitleaks, Trivy,
  hadolint) follow the same rule.

| Path | Gate | Seeded issue |
|------|------|--------------|
| `dependency-audit/vulnerable-requirements.txt` | dependency audit (pip-audit) | Old pins with published advisories |
| `sast/vulnerable_app.py` | SAST (Semgrep) | FastAPI handlers with command injection (`shell=True`, `os.system`), `yaml.load`, `eval`, f-string SQL, `pickle.loads`. Raises on import. |

`rules/semgrep/python-security.py` (outside this directory) is also
deliberately vulnerable: it holds the annotated test cases for the vendored
Semgrep rules and is likewise excluded from the project scan.
