#!/usr/bin/env bash
# Local + CI self-test for the Dockerfile gate (hadolint + ShipSafe policy).
#
# Asserts:
#   1. project discovery (fixtures/ excluded)          -> PASS  (exit 0), finds demo-app/Dockerfile
#   2. fixtures/dockerfile/Dockerfile.vulnerable       -> FAIL  (exit 1), seeded hadolint + SS rules
#   3. project discovery WITHOUT the fixtures/ exclude -> ERROR (exit 2): forbid-path guard trips
#   4. missing USER (hadolint itself is silent)        -> FAIL  (exit 1) via SS002
#   5. inline `# hadolint ignore=` pragma              -> FAIL  (exit 1): pragma not honoured
#   6. HADOLINT_FAILURE_THRESHOLD=none in the env      -> fixture still FAIL: env can't weaken gate
#   7. empty Dockerfile                                -> ERROR (exit 2): nothing linted
#   8. unparseable Dockerfile                          -> ERROR (exit 2): hadolint DL1000
#   9. info-level finding only                         -> PASS  (exit 0): threshold is warning
#
# Needs hadolint on PATH (scripts/install_hadolint.sh). No network, no docker.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
GATE=(python3 scripts/dockerfile_lint.py)
FIXTURE="fixtures/dockerfile/Dockerfile.vulnerable"
PINNED="python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {  # check <name> <expected-exit> <required-substring...> -- <gate args...>
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out actual
  out="$("${GATE[@]}" "$@" 2>&1)"; actual=$?
  echo "$out" | head -n 20
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

command -v hadolint >/dev/null || { echo "hadolint not found; run scripts/install_hadolint.sh and add it to PATH"; exit 2; }
hadolint --version
echo

# 1. The real gate, exactly as CI runs it.
check "project Dockerfiles (fixtures/ excluded)" 0 "PASS - 1 Dockerfile(s)" -- \
  --discover . --exclude fixtures/ --forbid-path fixtures/

# 2. Fixture must fail with every seeded rule.
check "vulnerable fixture" 1 "FAIL" \
  "] DL4000" "] DL3007" "] DL3008" "] DL3013" "] DL3042" "] DL3003" "] DL4006" "] DL3002" "] DL3025" \
  "] SS001" "] SS002" "] SS003" "] SS004" -- "$FIXTURE"

# 3. Dropping the exclude must trip the guard.
check "fixtures/ exclusion guard" 2 "LINT PROBLEM" "forbidden path" -- --discover . --forbid-path fixtures/

# 4. hadolint alone does not notice a missing USER; the policy check does.
printf 'FROM %s\nCMD ["python", "-V"]\n' "$PINNED" > "$TMP/no-user.Dockerfile"
raw="$(hadolint --no-fail -f json "$TMP/no-user.Dockerfile")"
echo "raw hadolint on no-USER Dockerfile: $raw"
check "missing USER caught by policy" 1 "] SS002" -- "$TMP/no-user.Dockerfile"

# 5. Inline ignore pragmas are not honoured.
printf 'FROM %s\n# hadolint ignore=DL3008\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\nUSER 10001\n' \
  "$PINNED" > "$TMP/pragma.Dockerfile"
check "inline ignore pragma disabled" 1 "] DL3008" -- "$TMP/pragma.Dockerfile"

# 6. Environment variables cannot loosen the gate.
HADOLINT_FAILURE_THRESHOLD=none HADOLINT_IGNORE=DL3007,DL3008 check "HADOLINT_* env ignored" 1 "] DL3007" "] DL3008" -- "$FIXTURE"

# 7 + 8. Nothing linted must not pass.
: > "$TMP/empty.Dockerfile"
check "empty Dockerfile fails closed" 2 "no FROM instruction" -- "$TMP/empty.Dockerfile"
printf 'this is not a dockerfile\n{{{\n' > "$TMP/garbage.Dockerfile"
check "unparseable Dockerfile fails closed" 2 "could not parse" -- "$TMP/garbage.Dockerfile"

# 9. Info-level findings are reported but do not fail.
printf 'FROM %s\nRUN apt-get update && apt-get install -y --no-install-recommends curl=8.14.1-2\nUSER 10001\n' \
  "$PINNED" > "$TMP/info.Dockerfile"
check "info-level does not fail" 0 "PASS" "informational, does not fail" -- "$TMP/info.Dockerfile"

if [ "$failures" -ne 0 ]; then
  echo "dockerfile-lint self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "dockerfile-lint self-test: all expectations met"
