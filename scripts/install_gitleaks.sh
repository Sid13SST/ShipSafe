#!/usr/bin/env bash
# Install the pinned Gitleaks release binary (free OSS CLI, MIT licence) and
# verify it against a SHA-256 pinned in this file before extracting it.
#
# Usage: scripts/install_gitleaks.sh [dest-dir]   (default: .tools/bin)
# Then put dest-dir on PATH. Supports linux/darwin on x64/arm64.
#
# The checksums below were copied from the release's
# gitleaks_<version>_checksums.txt and are the pin: a download that does not
# match them is rejected, even if the upstream checksums file changes.
# To upgrade: bump GITLEAKS_VERSION, replace all four hashes from the new
# checksums file, rerun scripts/verify_secrets.sh.
set -euo pipefail

GITLEAKS_VERSION="8.30.1"
sha256_for() {
  case "$1" in
    linux_x64)    echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;;
    linux_arm64)  echo "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;;
    darwin_x64)   echo "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709" ;;
    darwin_arm64) echo "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5" ;;
    *) return 1 ;;
  esac
}

DEST="${1:-.tools/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
platform="${os}_${arch}"
expected="$(sha256_for "$platform")" || { echo "no pinned checksum for $platform" >&2; exit 2; }

tarball="gitleaks_${GITLEAKS_VERSION}_${platform}.tar.gz"
url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "downloading $url"
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 -o "$tmp/$tarball" "$url"

if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$tmp/$tarball" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$tarball" | cut -d' ' -f1)"
fi
if [ "$actual" != "$expected" ]; then
  echo "CHECKSUM MISMATCH for $tarball" >&2
  echo "  expected $expected" >&2
  echo "  actual   $actual" >&2
  exit 1
fi
echo "sha256 OK: $actual"

mkdir -p "$DEST"
tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks
install -m 0755 "$tmp/gitleaks" "$DEST/gitleaks"

installed="$("$DEST/gitleaks" version)"
if [ "$installed" != "$GITLEAKS_VERSION" ]; then
  echo "installed gitleaks reports version '$installed', expected $GITLEAKS_VERSION" >&2
  exit 1
fi
echo "installed gitleaks $installed to $DEST/gitleaks"
