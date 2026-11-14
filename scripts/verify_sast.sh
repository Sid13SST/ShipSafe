#!/usr/bin/env bash
# Local + CI self-test for the SAST gate (Semgrep, vendored rules, offline).
#
# Asserts:
#   1. every vendored rule passes its annotated tests (semgrep --test)
#   2. project scan (repo minus fixtures/ and the rule test file) -> PASS  (exit 0)
#   3. fixtures/sast/                                          -> FAIL  (exit 1), all seeded rules reported
#   4. project scan WITHOUT the fixtures/ exclude              -> ERROR (exit 2): forbid-path guard trips
#   5. a .py file that is not valid Python                     -> ERROR (exit 2): fails closed
#   6. a file with only an INFO-severity finding               -> PASS  (exit 0): threshold respected
#   7. an inline `# nosemgrep` comment                         -> FAIL  (exit 1): not honoured
#   8. a .semgrepignore file in the target                     -> ERROR (exit 2): not honoured
#
# Needs semgrep on PATH (pip install -r scripts/requirements-tools.txt).
# Needs no network access and no Semgrep account.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
GATE=(python3 scripts/sast.py)
RULE_TEST_FILE="rules/semgrep/python-security.py"
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off

check() {  # check <name> <expected-exit> <required-substring...> -- <gate args...>
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out actual
  out="$("${GATE[@]}" "$@" 2>&1)"; actual=$?
  echo "$out" | head -n 12
  if [ "$(echo "$out" | wc -l)" -gt 12 ]; then echo "  ... ($(echo "$out" | wc -l) lines total)"; fi
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

command -v semgrep >/dev/null || { echo "semgrep not found; pip install -r scripts/requirements-tools.txt"; exit 2; }
echo "semgrep $(semgrep --version 2>/dev/null)"
echo

# 1. Rule tests.
if out="$(semgrep --test --metrics=off --disable-version-check rules/semgrep 2>&1)"; then
  grep -E 'tests passed|✓' <<<"$out"
  echo "SELF-TEST OK   [vendored rule tests]: semgrep --test passed"
else
  echo "$out" | tail -n 20
  echo "SELF-TEST FAIL [vendored rule tests]: semgrep --test failed"; failures=$((failures+1))
fi
echo

# 2. Project scan, exactly as CI runs it.
check "project scan (fixtures/ excluded)" 0 "PASS" -- \
  . --exclude fixtures/ --exclude "$RULE_TEST_FILE" --forbid-path fixtures/

# 3. Fixture must fail with every seeded rule.
check "vulnerable fixture" 1 "FAIL" \
  shipsafe.fastapi-input-to-shell shipsafe.subprocess-shell-true shipsafe.os-system-non-literal \
  shipsafe.yaml-unsafe-load shipsafe.eval-exec-non-literal shipsafe.sql-string-formatting \
  shipsafe.pickle-load -- fixtures/sast

# 4. Dropping the exclude must trip the guard, not silently scan fixtures.
check "fixtures/ exclusion guard" 2 "forbidden 'fixtures/'" -- \
  . --exclude "$RULE_TEST_FILE" --forbid-path fixtures/

# 5. Unparseable Python must not pass.
mkdir -p "$TMP/broken" "$TMP/info"
printf 'def f(:\n    pass\n' > "$TMP/broken/broken.py"
check "invalid python fails closed" 2 "ERROR" "not valid Python" -- "$TMP/broken"

# 6. INFO-only findings are reported but do not fail.
printf 'import hashlib\n\nhashlib.md5(b"checksum only")\n' > "$TMP/info/checksum.py"
check "INFO severity does not fail" 0 "PASS" "shipsafe.weak-hash (informational" -- "$TMP/info"

# 7. Inline `# nosemgrep` must not suppress a finding.
mkdir -p "$TMP/nosem"
printf 'def calc(expr):\n    return eval(expr)  # nosemgrep\n' > "$TMP/nosem/calc.py"
check "inline nosemgrep ignored" 1 "shipsafe.eval-exec-non-literal" -- "$TMP/nosem"

# 8. A .semgrepignore must not silently drop files from the scan.
mkdir -p "$TMP/semignore"
printf 'def calc(expr):\n    return eval(expr)\n' > "$TMP/semignore/calc.py"
printf 'calc.py\n' > "$TMP/semignore/.semgrepignore"
check ".semgrepignore refused" 2 "ERROR" ".semgrepignore present" -- "$TMP/semignore"

if [ "$failures" -ne 0 ]; then
  echo "sast self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "sast self-test: all expectations met"
