#!/usr/bin/env bash
# Local + CI self-test for the dependency-audit gate.
#
# Reproduces the gate verdicts without GitHub Actions and asserts them:
#   1. demo-app pinned requirements        -> PASS  (exit 0)
#   2. fixtures/ vulnerable requirements   -> FAIL  (exit 1) with the seeded packages reported
#   3. an unpinned requirement             -> ERROR (exit 2)  (gate fails closed)
#
# Needs pip-audit on PATH (pip install -r scripts/requirements-tools.txt) and
# network access to PyPI's vulnerability data. Exits non-zero if any
# expectation is not met.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE=(python3 "$ROOT/scripts/dependency_audit.py")
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {  # check <name> <expected-exit> <file> [required-substring...]
  local name="$1" expected="$2" file="$3"; shift 3
  local out actual
  out="$("${GATE[@]}" "$file" 2>&1)"; actual=$?
  echo "$out" | head -n 8
  [ "$(echo "$out" | wc -l)" -gt 8 ] && echo "  ... ($(echo "$out" | wc -l) lines total)"
  if [ "$actual" -ne "$expected" ]; then
    echo "SELF-TEST FAIL [$name]: expected exit $expected, got $actual"; failures=$((failures+1)); return
  fi
  for needle in "$@"; do
    if ! grep -q -- "$needle" <<<"$out"; then
      echo "SELF-TEST FAIL [$name]: output missing '$needle'"; failures=$((failures+1)); return
    fi
  done
  echo "SELF-TEST OK   [$name]: exit $actual as expected"
  echo
}

command -v pip-audit >/dev/null || { echo "pip-audit not found; pip install -r scripts/requirements-tools.txt"; exit 2; }

check "clean app runtime deps" 0 "$ROOT/demo-app/requirements.txt" "PASS"
check "clean app dev deps"     0 "$ROOT/demo-app/requirements-dev.txt" "PASS"
check "vulnerable fixture"     1 "$ROOT/fixtures/dependency-audit/vulnerable-requirements.txt" \
  "FAIL" "requests==2.19.1" "jinja2==2.10" "pyyaml==5.3" "urllib3==1.24.1"
printf 'requests\n' > "$TMP/unpinned.txt"
check "unpinned requirement"   2 "$TMP/unpinned.txt" "ERROR"

if [ "$failures" -ne 0 ]; then
  echo "dependency-audit self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "dependency-audit self-test: all expectations met"
