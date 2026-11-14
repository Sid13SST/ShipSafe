#!/usr/bin/env bash
# Self-test for the waiver mechanism with the real gate tools (offline).
#
# Asserts, for a Dockerfile with exactly one policy finding (SS001) and a
# Python file with exactly one SAST finding (eval):
#   1. no waivers                                   -> FAIL  (exit 1)
#   2. active, matching waiver                      -> PASS  (exit 0), reported as WAIVED
#   3. active waiver scoped to another path         -> FAIL  (exit 1)
#   4. expired waiver (fixtures/waivers/expired.yml)-> FAIL  (exit 1), even on a clean file
#   5. waiver for the secrets gate                  -> ERROR (exit 2)
#   6. YAML outside the supported subset            -> ERROR (exit 2)
#   7. expiry more than 90 days ahead               -> ERROR (exit 2)
#   8. SAST: active waiver for the eval finding     -> PASS  (exit 0)
#   9. the repository's own .shipsafe/waivers.yml   -> valid (gate runs normally)
#
# Needs hadolint and semgrep on PATH. No network.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off

check() {  # check <name> <expected-exit> <required-substring...> -- <command...>
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out actual
  out="$("$@" 2>&1)"; actual=$?
  echo "$out" | head -n 8
  if [ "$actual" -ne "$expected" ]; then
    echo "SELF-TEST FAIL [$name]: expected exit $expected, got $actual"; failures=$((failures+1)); echo; return
  fi
  for needle in "${needles[@]}"; do
    if ! grep -qF -- "$needle" <<<"$out"; then
      echo "SELF-TEST FAIL [$name]: output missing '$needle'"; failures=$((failures+1)); echo; return
    fi
  done
  echo "SELF-TEST OK   [$name]: exit $actual as expected"
  echo
}

for tool in hadolint semgrep; do
  command -v "$tool" >/dev/null || { echo "$tool not found on PATH"; exit 2; }
done

soon="$(python3 -c 'import datetime; print(datetime.date.today() + datetime.timedelta(days=30))')"
far="$(python3 -c 'import datetime; print(datetime.date.today() + datetime.timedelta(days=120))')"
reason="Self-test: temporary exception while the base image digest is reviewed"
waiver() {  # waiver <file> <id> <gate> <expires> [scope]
  { echo "waivers:"; echo "  - id: $2"; echo "    gate: $3"; echo "    reason: \"$reason\"";
    echo "    expires: $4"; if [ -n "${5:-}" ]; then echo "    scope: $5"; fi; } > "$1"
}

# A Dockerfile whose only finding is SS001 (tag but no digest).
mkdir -p "$TMP/app"
printf 'FROM python:3.13.18-slim-trixie\nUSER 10001\nCMD ["python", "-V"]\n' > "$TMP/app/Dockerfile"
clean_df="$TMP/clean.Dockerfile"
printf 'FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90\nUSER 10001\nCMD ["python", "-V"]\n' > "$clean_df"
DL=(python3 scripts/dockerfile_lint.py "$TMP/app/Dockerfile")

waiver "$TMP/none.yml" CVE-0000-0000 container-scan "$soon"
check "no matching waiver"              1 "] SS001"          -- "${DL[@]}" --waivers "$TMP/none.yml"
waiver "$TMP/active.yml" SS001 dockerfile-lint "$soon" "$TMP/app/Dockerfile"
check "active waiver"                   0 "PASS" "WAIVED:" "until $soon" -- "${DL[@]}" --waivers "$TMP/active.yml"
waiver "$TMP/other-scope.yml" SS001 dockerfile-lint "$soon" "services/*/Dockerfile"
check "waiver scoped elsewhere"         1 "] SS001" "unused waiver" -- "${DL[@]}" --waivers "$TMP/other-scope.yml"
check "expired waiver fails clean file" 1 "EXPIRED WAIVER" -- \
  python3 scripts/dockerfile_lint.py "$clean_df" --waivers fixtures/waivers/expired.yml
check "secrets waiver rejected"         2 "secrets findings cannot be waived" -- \
  "${DL[@]}" --waivers fixtures/waivers/secrets-waiver.yml
check "unsupported YAML rejected"       2 "unsupported YAML value" -- "${DL[@]}" --waivers fixtures/waivers/bad-syntax.yml
waiver "$TMP/far.yml" SS001 dockerfile-lint "$far"
check "expiry beyond 90 days rejected"  2 "more than 90 days ahead" -- "${DL[@]}" --waivers "$TMP/far.yml"

# SAST: one eval finding, waived by rule id + path.
mkdir -p "$TMP/src"
printf 'def calc(expr):\n    return eval(expr)\n' > "$TMP/src/calc.py"
waiver "$TMP/sast.yml" shipsafe.eval-exec-non-literal sast "$soon" "$TMP/src/calc.py"
check "SAST without waiver"             1 "shipsafe.eval-exec-non-literal" -- python3 scripts/sast.py "$TMP/src" --waivers "$TMP/none.yml"
check "SAST with active waiver"         0 "PASS" "WAIVED:" -- python3 scripts/sast.py "$TMP/src" --waivers "$TMP/sast.yml"

# The repository's own waivers file must stay valid.
check "repo .shipsafe/waivers.yml valid" 0 "PASS" -- python3 scripts/dockerfile_lint.py "$clean_df"

if [ "$failures" -ne 0 ]; then
  echo "waivers self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "waivers self-test: all expectations met"
