#!/usr/bin/env bash
# Self-test for cross-repository reuse: run every gate the way the reusable
# workflows do - ShipSafe's scripts from a separate tooling directory, with
# the working directory set to a different ("consumer") repository.
#
# Asserts, on a small, clean throwaway consumer repo:
#   1. dependency audit, SAST, secrets (git history), Dockerfile lint and the
#      Trivy config scan all PASS, and none of them scans the tooling copy;
#   2. a fake token in the CONSUMER's fixtures/ FAILS the secrets gate -
#      ShipSafe's own fixtures/ allowlist is never applied to other repos;
#   3. the consumer's .shipsafe/waivers.yml is the one that is read
#      (an expired waiver there FAILS the gate);
#   4. ShipSafe's own .shipsafe/waivers.yml and fixtures do not affect it.
#
# Needs pip-audit, semgrep, gitleaks, hadolint and trivy on PATH, git, and
# network access for pip-audit and Trivy's checks bundle.
# Set SHIPSAFE_TRIVY_CACHE to reuse a Trivy cache directory.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off
TRIVY_ARGS=()
if [ -n "${SHIPSAFE_TRIVY_CACHE:-}" ]; then TRIVY_ARGS=(--cache-dir "$SHIPSAFE_TRIVY_CACHE"); fi

for tool in pip-audit semgrep gitleaks hadolint trivy git; do
  command -v "$tool" >/dev/null || { echo "$tool not found on PATH"; exit 2; }
done

check() {  # check <name> <expected-exit> <required-substring...> -- <command...>
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out actual
  out="$("$@" 2>&1)"; actual=$?
  echo "$out" | head -n 6
  if [ "$actual" -ne "$expected" ]; then
    echo "SELF-TEST FAIL [$name]: expected exit $expected, got $actual"; failures=$((failures+1)); echo; return
  fi
  for needle in "${needles[@]}"; do
    if ! grep -qF -- "$needle" <<<"$out"; then
      echo "SELF-TEST FAIL [$name]: output missing '$needle'"; failures=$((failures+1)); echo; return
    fi
  done
  if grep -qF -- "$TOOLING" <<<"$out"; then
    echo "SELF-TEST FAIL [$name]: output mentions the tooling directory - it was scanned"; failures=$((failures+1)); echo; return
  fi
  echo "SELF-TEST OK   [$name]: exit $actual as expected"
  echo
}

# --- tooling: the tracked files of this ShipSafe checkout, outside the consumer
TOOLING="$TMP/tooling"
mkdir -p "$TOOLING"
( cd "$ROOT" && git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$TOOLING" )
echo "tooling copy: $(find "$TOOLING" -type f | wc -l) files (includes ShipSafe's fixtures/ and .gitleaks.toml)"

# --- consumer: a tiny, clean, unrelated repository
C="$TMP/consumer"
mkdir -p "$C/src"
git_c=(git -C "$C" -c user.name=consumer -c user.email=consumer@example.invalid -c commit.gpgsign=false)
git -C "$C" init -q
printf 'idna==3.20\n' > "$C/requirements.txt"
printf 'def add(a: int, b: int) -> int:\n    return a + b\n' > "$C/src/calc.py"
printf 'FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90\nUSER 10001\nHEALTHCHECK CMD ["python", "-c", "print(1)"]\nCMD ["python", "-V"]\n' > "$C/Dockerfile"
git -C "$C" add -A && "${git_c[@]}" commit -qm "consumer app"
cd "$C" || exit 2

T="$TOOLING/scripts"
check "dependency audit (consumer)" 0 "PASS" -- python3 "$T/dependency_audit.py" requirements.txt
check "SAST (consumer)" 0 "PASS - 1 file(s) scanned" -- python3 "$T/sast.py" .
check "secrets, git history (consumer)" 0 "PASS" "1 commit(s)" -- python3 "$T/secrets_scan.py" . --mode git
check "Dockerfile lint (consumer)" 0 "PASS - 1 Dockerfile(s)" -- python3 "$T/dockerfile_lint.py" --discover .
check "Trivy config scan (consumer)" 0 "PASS, 1 target(s)" -- python3 "$T/container_scan.py" config . "${TRIVY_ARGS[@]}"

# 2. ShipSafe's fixtures/ allowlist must not apply to the consumer.
mkdir -p fixtures
printf 'TOKEN=%s\n' "$(printf '%s%s%s' 'gh' 'p_' 'ConsumerFakeTokenNotRealAtAll00000000')" > fixtures/creds.env
git add fixtures/creds.env && "${git_c[@]}" commit -qm "add fixture"
check "consumer fixtures/ not allowlisted" 1 "FAIL" "fixtures/creds.env:1 github-pat" -- \
  python3 "$T/secrets_scan.py" . --mode git
git rm -q fixtures/creds.env && "${git_c[@]}" commit -qm "remove fixture"

# 3. The consumer's waivers file is read (expired waiver fails a clean scan).
mkdir -p .shipsafe
printf 'waivers:\n  - id: SS001\n    gate: dockerfile-lint\n    reason: "Consumer test: expired waiver must fail"\n    expires: 2020-01-01\n' > .shipsafe/waivers.yml
check "consumer waivers file honoured" 1 "EXPIRED WAIVER" -- python3 "$T/dockerfile_lint.py" --discover .
rm -rf .shipsafe

if [ "$failures" -ne 0 ]; then
  echo "reuse self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "reuse self-test: all expectations met"
