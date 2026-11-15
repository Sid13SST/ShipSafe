#!/usr/bin/env bash
# Install the pinned hadolint release binary (free OSS, GPL-3.0) and verify it
# against a SHA-256 pinned in this file before installing it.
#
# Usage: scripts/install_hadolint.sh [dest-dir]   (default: .tools/bin)
# Then put dest-dir on PATH. Supports linux/macOS on x86_64/arm64.
#
# The hashes below were copied from the release's per-asset
# hadolint-<platform>.sha256 files. The linux-x86_64 hash was also
# cross-checked against /bin/hadolint inside the official
# hadolint/hadolint:v2.14.0 image (identical).
# Why 2.14.0 and not 2.15.x: 2.15.1 publishes no checksum files that could be
# verified from the build environment, and pinning a hash computed from a
# single download would only be trust-on-first-use. See docs/TASKS.md.
# To upgrade: bump HADOLINT_VERSION, replace all four hashes from the new
# release's .sha256 files, rerun scripts/verify_dockerfile_lint.sh.
set -euo pipefail

HADOLINT_VERSION="2.14.0"
sha256_for() {
  case "$1" in
    linux-x86_64) echo "6bf226944684f56c84dd014e8b979d27425c0148f61b3bd99bcc6f39e9dc5a47" ;;
    linux-arm64)  echo "331f1d3511b84a4f1e3d18d52fec284723e4019552f4f47b19322a53ce9a40ed" ;;
    macos-x86_64) echo "2b69a853433f1eca522ffb921cd490bd1321424d03331fd8390f93b7fb4a02e9" ;;
    macos-arm64)  echo "3625e2e9f43dcfe7bd38738a5f5520ed50ce39ed28485266e6803dd7bc197b10" ;;
    *) return 1 ;;
  esac
}

DEST="${1:-.tools/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
platform="${os}-${arch}"
expected="$(sha256_for "$platform")" || { echo "no pinned checksum for $platform" >&2; exit 2; }

asset="hadolint-${platform}"
url="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "downloading $url"
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 -o "$tmp/$asset" "$url"

if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
fi
if [ "$actual" != "$expected" ]; then
  echo "CHECKSUM MISMATCH for $asset" >&2
  echo "  expected $expected" >&2
  echo "  actual   $actual" >&2
  exit 1
fi
echo "sha256 OK: $actual"

mkdir -p "$DEST"
install -m 0755 "$tmp/$asset" "$DEST/hadolint"

installed="$("$DEST/hadolint" --version)"
case "$installed" in
  *" $HADOLINT_VERSION"*) ;;
  *) echo "installed hadolint reports '$installed', expected $HADOLINT_VERSION" >&2; exit 1 ;;
esac
echo "installed $installed to $DEST/hadolint"
