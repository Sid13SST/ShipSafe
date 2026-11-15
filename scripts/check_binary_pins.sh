#!/usr/bin/env bash
# Report whether the binaries pinned in scripts/install_*.sh have newer
# upstream releases. Dependabot cannot update these pins (they are a version
# plus per-platform SHA-256 inside a shell script), so this check makes
# staleness visible instead.
#
# It only REPORTS. Bumping a pin stays a manual, reviewed change: read the
# release notes, take the hashes from the upstream checksums file (verify its
# signature where one is published), wait out a cooldown for brand-new
# releases, then rerun the gate's self-test.
#
# Usage: scripts/check_binary_pins.sh [--strict]
#   --strict  exit 1 if any pin is behind (default: always exit 0 unless the
#             check itself fails, which exits 2)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
strict=0
[ "${1:-}" = "--strict" ] && strict=1

# tool | install script | version variable | upstream repository
TOOLS=(
  "gitleaks|install_gitleaks.sh|GITLEAKS_VERSION|https://github.com/gitleaks/gitleaks"
  "hadolint|install_hadolint.sh|HADOLINT_VERSION|https://github.com/hadolint/hadolint"
  "trivy|install_trivy.sh|TRIVY_VERSION|https://github.com/aquasecurity/trivy"
)

behind=0
errors=0
report="| Tool | Pinned | Latest release tag | Status |\n|------|--------|--------------------|--------|\n"
for entry in "${TOOLS[@]}"; do
  IFS='|' read -r tool script var repo <<<"$entry"
  pinned="$(sed -n "s/^${var}=\"\([0-9.]*\)\"$/\1/p" "$ROOT/scripts/$script")"
  if [ -z "$pinned" ]; then
    echo "ERROR: could not read $var from scripts/$script" >&2; errors=$((errors+1)); continue
  fi
  if ! tags="$(git ls-remote --tags --refs "$repo" 2>/dev/null)"; then
    echo "ERROR: could not list tags of $repo" >&2; errors=$((errors+1)); continue
  fi
  latest="$(sed -n 's|.*refs/tags/v\([0-9]*\.[0-9]*\.[0-9]*\)$|\1|p' <<<"$tags" | sort -V | tail -n 1)"
  if [ -z "$latest" ]; then
    echo "ERROR: no release tags found for $repo" >&2; errors=$((errors+1)); continue
  fi
  if [ "$pinned" = "$latest" ]; then
    status="up to date"
  elif [ "$(printf '%s\n%s\n' "$pinned" "$latest" | sort -V | tail -n 1)" = "$latest" ]; then
    status="NEWER RELEASE AVAILABLE - review before bumping"; behind=$((behind+1))
  else
    status="pinned is ahead of latest tag (check)"
  fi
  report+="| $tool | $pinned | $latest | $status |\n"
done

printf '%b' "$report"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### Binary tool pins"; echo; printf '%b' "$report"; echo
    echo "Tags are not releases: a newer tag may be a pre-release or not yet have published checksums."
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [ "$errors" -ne 0 ]; then exit 2; fi
if [ "$behind" -ne 0 ]; then
  echo "$behind pin(s) behind upstream (informational)"
  [ "$strict" -eq 1 ] && exit 1
fi
exit 0
