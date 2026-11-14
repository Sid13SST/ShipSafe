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
- Production gates (the ones run on `demo-app/`) must never scan `fixtures/`;
  later scanners (Semgrep, Gitleaks, Trivy, hadolint) will exclude this path
  explicitly for the app scan.

| Path | Gate | Seeded issue |
|------|------|--------------|
| `dependency-audit/vulnerable-requirements.txt` | dependency audit (pip-audit) | Old pins with published advisories |
