#!/usr/bin/env bash
# Local + CI self-test for the container-scan gate (Trivy, pinned binary).
#
# Asserts:
#   1. config scan of the project (fixtures/ skipped)      -> PASS  (exit 0)
#   2. config scan of fixtures/container-scan/              -> FAIL  (exit 1): DS-0001/0002/0029
#   3. config scan WITHOUT the fixtures skip                -> ERROR (exit 2): forbid-path guard
#   4. a Dockerfile with an inline trivy:ignore comment     -> ERROR (exit 2): suppression refused
#   5. trivy.yaml + .trivyignore + TRIVY_* env in the cwd   -> still FAIL: none of them is honoured
#   6. an empty directory                                   -> ERROR (exit 2): nothing scanned
#   7. old-base-image fixture, read from the registry       -> FAIL  (exit 1): fixable HIGH/CRITICAL
#      (never run: --image-src remote)                         vulns + image-config misconfig
#   8. an image reference that does not exist               -> ERROR (exit 2)
#
# Needs trivy on PATH (scripts/install_trivy.sh) and network access to the
# Trivy DB (mirror.gcr.io) and the fixture image registry. No Docker needed.
# Set SHIPSAFE_TRIVY_CACHE to reuse a DB cache directory.
#
# Time-variance: check 7 asserts only that fixable HIGH/CRITICAL findings
# exist, never exact counts, because advisory data changes daily.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
CACHE_ARGS=()
if [ -n "${SHIPSAFE_TRIVY_CACHE:-}" ]; then CACHE_ARGS=(--cache-dir "$SHIPSAFE_TRIVY_CACHE"); fi
GATE=(python3 "$ROOT/scripts/container_scan.py")
FIXDIR="fixtures/container-scan"
OLD_IMAGE="$(grep -v '^#' "$FIXDIR/old-base-image.txt" | grep -v '^[[:space:]]*$' | head -n 1)"
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {  # check <name> <expected-exit> <required-substring...> -- <gate args...>   (CHECK_CWD: run dir)
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out actual
  out="$(cd "${CHECK_CWD:-$ROOT}" && "${GATE[@]}" "$@" "${CACHE_ARGS[@]}" 2>&1)"; actual=$?
  echo "$out" | head -n 10
  if [ "$(echo "$out" | wc -l)" -gt 10 ]; then echo "  ... ($(echo "$out" | wc -l) lines total)"; fi
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

command -v trivy >/dev/null || { echo "trivy not found; run scripts/install_trivy.sh and add it to PATH"; exit 2; }
trivy --version 2>/dev/null | head -n 1
echo

# 1-3. Config scan of the project, the fixture, and the exclusion guard.
check "config scan, project (fixtures/ skipped)" 0 "PASS" -- config . --skip-dir fixtures --forbid-path fixtures/
check "config scan, fixture" 1 "FAIL" "[misconfig] DS-0001" "[misconfig] DS-0002" "[misconfig] DS-0029" -- \
  config "$FIXDIR"
check "config scan, fixtures/ exclusion guard" 2 "forbidden path fixtures/" -- config . --forbid-path fixtures/

# 4. Inline suppression comments are refused.
mkdir -p "$TMP/inline"
printf '# %s\nFROM debian:latest\nUSER root\n' "trivy:ignore:DS-0001" > "$TMP/inline/Dockerfile"
check "inline trivy:ignore refused" 2 "inline trivy:ignore" -- config "$TMP/inline"

# 5. Local config/ignore files and TRIVY_* env cannot weaken the gate.
mkdir -p "$TMP/override"
cp "$FIXDIR/Dockerfile.misconfig" "$TMP/override/Dockerfile"
printf 'severity:\n  - CRITICAL\n' > "$TMP/override/trivy.yaml"
printf 'DS-0001\nDS-0002\nDS-0026\nDS-0029\n' > "$TMP/override/.trivyignore"
CHECK_CWD="$TMP/override" TRIVY_SEVERITY=CRITICAL TRIVY_IGNOREFILE=.trivyignore \
  check "trivy.yaml/.trivyignore/TRIVY_* ignored" 1 "[misconfig] DS-0001" "[misconfig] DS-0029" -- config .

# 6. Scanning nothing must not pass.
mkdir -p "$TMP/empty"
check "empty directory fails closed" 2 "found no files" -- config "$TMP/empty"

# 7. Old base image: read from the registry, never run.
check "old base image fixture" 1 "FAIL" "[vuln] CVE-" "CRITICAL" "fixed in" "[misconfig] DS-0002" -- \
  image "$OLD_IMAGE" --image-src remote --platform linux/amd64

# 8. A reference that cannot be resolved is an error, not a pass.
check "unresolvable image fails closed" 2 "ERROR" -- \
  image "mirror.gcr.io/library/python@sha256:0000000000000000000000000000000000000000000000000000000000000000" \
  --image-src remote --platform linux/amd64

if [ "$failures" -ne 0 ]; then
  echo "container-scan self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "container-scan self-test: all expectations met"
