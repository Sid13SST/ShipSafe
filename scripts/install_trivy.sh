#!/usr/bin/env bash
# Install the pinned Trivy release binary (free OSS, Apache-2.0) and verify
# it against a SHA-256 pinned in this file before extracting it.
#
# Usage: scripts/install_trivy.sh [dest-dir]   (default: .tools/bin)
# Then put dest-dir on PATH. Supports linux/macOS on x64/arm64.
#
# SUPPLY-CHAIN NOTE: Trivy's own distribution was compromised in March 2026
# (CVE-2026-33634 / GHSA-69fq-xp46-6x23): a malicious v0.69.4 release binary,
# malicious v0.69.5/v0.69.6 images, and hijacked tags on the trivy-action and
# setup-trivy GitHub Actions. ShipSafe therefore:
#   - never uses trivy-action, setup-trivy, or a Trivy container image;
#   - pins a release (0.76.2) published well after the incident;
#   - pins the tarball SHA-256 in this repo instead of trusting a checksums
#     file fetched at install time.
# The hashes below were copied from trivy_0.76.2_checksums.txt. The
# linux-64bit binary was cross-checked byte-for-byte against /usr/local/bin/trivy
# in both aquasec/trivy:0.76.2 (Docker Hub) and ghcr.io/aquasecurity/trivy:0.76.2.
# The release's Sigstore bundle was NOT verified (no cosign in the pinning
# environment) - see docs/TASKS.md.
# To upgrade: bump TRIVY_VERSION, replace all four hashes from the new
# checksums file (verify its signature), rerun scripts/verify_container_scan.sh.
set -euo pipefail

TRIVY_VERSION="0.76.2"
sha256_for() {
  case "$1" in
    Linux-64bit)  echo "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf" ;;
    Linux-ARM64)  echo "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3" ;;
    macOS-64bit)  echo "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b" ;;
    macOS-ARM64)  echo "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8" ;;
    *) return 1 ;;
  esac
}

DEST="${1:-.tools/bin}"

case "$(uname -s)" in
  Linux) os=Linux ;;
  Darwin) os=macOS ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=64bit ;;
  aarch64|arm64) arch=ARM64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
platform="${os}-${arch}"
expected="$(sha256_for "$platform")" || { echo "no pinned checksum for $platform" >&2; exit 2; }

tarball="trivy_${TRIVY_VERSION}_${platform}.tar.gz"
url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tarball}"

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
tar -xzf "$tmp/$tarball" -C "$tmp" trivy
install -m 0755 "$tmp/trivy" "$DEST/trivy"

installed="$("$DEST/trivy" --version 2>/dev/null | sed -n 's/^Version: //p' | head -n 1)"
if [ "$installed" != "$TRIVY_VERSION" ]; then
  echo "installed trivy reports version '$installed', expected $TRIVY_VERSION" >&2
  exit 1
fi
echo "installed trivy $installed to $DEST/trivy"
