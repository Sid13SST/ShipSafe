# DELIBERATELY VULNERABLE FIXTURE - FAKE, NON-FUNCTIONAL CREDENTIAL.
# Used only by scripts/verify_secrets.sh to prove the secrets gate (Gitleaks)
# FAILS on a hard-coded API key. The value is a made-up random string that
# authenticates against nothing. Never import or run this file.
#
# Expected finding: generic-api-key (line 9)
raise RuntimeError("ShipSafe fixture: deliberately vulnerable, never import or run")

api_key = "Zq8vR3nLx7Tp2Wm9Kd4Fh6Jc1Bs5Ng0Y"
