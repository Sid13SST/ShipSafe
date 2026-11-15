#!/usr/bin/env bash
# Local + CI self-test for the secrets gate (Gitleaks, pinned binary).
#
# Asserts:
#   1. project working tree, .gitleaks.toml            -> PASS  (exit 0)
#   2. project full git history, .gitleaks.toml        -> PASS  (exit 0)
#   3. fixtures/secrets/, default rules (no allowlist) -> FAIL  (exit 1), all 4 seeded rules
#   4. project tree, default rules (no allowlist)      -> FAIL, and every finding is under
#                                                         fixtures/ (the allowlist hides only them)
#   5. a .gitleaksignore in the target                 -> ERROR (exit 2), gitleaks not run
#   6. an inline gitleaks:allow comment                -> FAIL  (exit 1), comment ignored
#   7. an empty directory                              -> ERROR (exit 2), 0 bytes scanned
#   8. git mode on a shallow clone                     -> ERROR (exit 2), history incomplete
#   9. a secret committed then deleted (git mode)      -> FAIL  (exit 1), history is scanned
#
# Needs gitleaks on PATH (scripts/install_gitleaks.sh) and git. No network.
# Temporary fake tokens are assembled at runtime from pieces so this script
# itself contains nothing that matches a rule (check 1 proves it).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
GATE=(python3 scripts/secrets_scan.py)
DEFAULT_ONLY="rules/gitleaks/default-only.toml"
failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

LAST_OUT=""
check() {  # check <name> <expected-exit> <required-substring...> -- <gate args...>
  local name="$1" expected="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local actual
  LAST_OUT="$("${GATE[@]}" "$@" 2>&1)"; actual=$?
  echo "$LAST_OUT" | head -n 12
  if [ "$actual" -ne "$expected" ]; then
    echo "SELF-TEST FAIL [$name]: expected exit $expected, got $actual"; failures=$((failures+1)); echo; return 1
  fi
  for needle in "${needles[@]}"; do
    if ! grep -qF -- "$needle" <<<"$LAST_OUT"; then
      echo "SELF-TEST FAIL [$name]: output missing '$needle'"; failures=$((failures+1)); echo; return 1
    fi
  done
  echo "SELF-TEST OK   [$name]: exit $actual as expected"
  echo
}

command -v gitleaks >/dev/null || { echo "gitleaks not found; run scripts/install_gitleaks.sh and add it to PATH"; exit 2; }
echo "gitleaks $(gitleaks version)"
echo

# A fake, non-functional GitHub-style token (invalid checksum), built from pieces.
fake_token="$(printf '%s%s%s' 'gh' 'p_' 'ShipSafeSelfTestFakeTokenNotReal0000')"
git_c=(git -c user.name=shipsafe-selftest -c user.email=selftest@example.invalid -c commit.gpgsign=false)

# 1 + 2. The real gate, both modes.
check "project working tree" 0 "PASS" -- . --mode dir
check "project git history" 0 "PASS" "commit(s)" -- . --mode git

# 3. Fixture must fail with every seeded rule.
check "fixtures/secrets with default rules" 1 "FAIL" \
  "fake-credentials.env:9 aws-access-token" "fake-credentials.env:10 github-pat" \
  "fake_private_key.pem:5 private-key" "fake_settings.py:9 generic-api-key" -- \
  fixtures/secrets --config "$DEFAULT_ONLY"

# 4. Without the allowlist the project fails - and only because of fixtures/.
if check "project without allowlist" 1 "FAIL" "fixtures/secrets/" -- . --mode dir --config "$DEFAULT_ONLY"; then
  outside="$(grep -E '^  - ' <<<"$LAST_OUT" | grep -v '^  - fixtures/' || true)"
  if [ -n "$outside" ]; then
    echo "SELF-TEST FAIL [allowlist scope]: findings outside fixtures/:"; echo "$outside"; failures=$((failures+1))
  else
    echo "SELF-TEST OK   [allowlist scope]: every default-rule finding is under fixtures/"
  fi
  echo
fi

# 5. .gitleaksignore must not be able to hide findings.
mkdir -p "$TMP/ignorefile"
printf 'TOKEN=%s\n' "$fake_token" > "$TMP/ignorefile/app.env"
printf 'app.env:github-pat:1\n' > "$TMP/ignorefile/.gitleaksignore"
check ".gitleaksignore rejected" 2 "ERROR" ".gitleaksignore present" -- "$TMP/ignorefile"

# 6. Inline allow comments must not suppress.
mkdir -p "$TMP/inline"
printf 'TOKEN=%s  # %s\n' "$fake_token" "gitleaks:allow" > "$TMP/inline/app.env"
check "inline gitleaks:allow ignored" 1 "FAIL" "github-pat" -- "$TMP/inline"

# 7. Scanning nothing must not pass.
mkdir -p "$TMP/empty"
check "empty target fails closed" 2 "ERROR" "0 bytes" -- "$TMP/empty"

# 8 + 9. History checks on a throwaway repo.
repo="$TMP/history"
mkdir -p "$repo" && git -C "$repo" init -q
printf 'TOKEN=%s\n' "$fake_token" > "$repo/app.env"
git -C "$repo" add app.env && "${git_c[@]}" -C "$repo" commit -qm "add config"
git -C "$repo" rm -q app.env && "${git_c[@]}" -C "$repo" commit -qm "remove config"
printf 'clean\n' > "$repo/README" && git -C "$repo" add README && "${git_c[@]}" -C "$repo" commit -qm "readme"
git clone -q --depth 1 "file://$repo" "$TMP/shallow"
check "shallow clone fails closed" 2 "ERROR" "shallow clone" -- "$TMP/shallow" --mode git
check "deleted secret found in history" 1 "FAIL" "app.env:1 github-pat @" -- "$repo" --mode git

if [ "$failures" -ne 0 ]; then
  echo "secrets self-test: $failures expectation(s) NOT met"; exit 1
fi
echo "secrets self-test: all expectations met"
