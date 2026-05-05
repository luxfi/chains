#!/usr/bin/env bash
# fetch-luxcpp.sh — download pre-built luxcpp libs so external Go consumers
# can `go build` this package without a local luxcpp source checkout.
#
# Mirrors the layout assumed by cevm_cgo.go:
#   ${SRCDIR}/../../../../luxcpp/cevm/lib/evm/gpu/             (headers)
#   ${SRCDIR}/../../../../luxcpp/cevm/build/lib/               (libevm.*)
#   ${SRCDIR}/../../../../luxcpp/cevm/build/lib/evm/           (libevm-gpu.*)
#   ${SRCDIR}/../../../../luxcpp/cevm/build/lib/evm/luxcpp-gpu (libluxgpu.*)
#   ${SRCDIR}/../../../../luxcpp/cevm/build/lib/cevm_precompiles
#
# In a source-tree build (~/work/lux/chains/evm/cevm/) ${SRCDIR}/../../../../
# resolves to ~/work/, so the libs live at ~/work/luxcpp/.
# In a module-cache build it resolves to $GOMODCACHE/github.com/luxfi/, so the
# libs must live at $GOMODCACHE/github.com/luxfi/luxcpp/. This script targets
# whichever location is "above" $SRCDIR.
#
# Idempotent: skips when libs already present.
# Verified: SHA-256 pinned in luxcpp-SHA256SUMS next to this script.
#
# Usage: ./fetch-luxcpp.sh
# Env:
#   LUXCPP_VERSION — override version (default: contents of ./LUXCPP_VERSION)
#   LUXCPP_FORCE   — set to 1 to re-download even when libs exist
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Version: env override → VERSION file → hard fail
VERSION="${LUXCPP_VERSION:-}"
if [[ -z "$VERSION" ]]; then
  if [[ -f LUXCPP_VERSION ]]; then
    VERSION="$(tr -d '[:space:]' < LUXCPP_VERSION)"
  else
    echo "fetch-luxcpp.sh: no LUXCPP_VERSION set and no ./LUXCPP_VERSION file" >&2
    exit 1
  fi
fi

# Platform detection — match accel's coverage (linux+darwin, amd64+arm64).
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
case "$UNAME_S" in
  Darwin) PLATFORM=darwin ;;
  Linux)  PLATFORM=linux ;;
  *) echo "fetch-luxcpp.sh: unsupported OS $UNAME_S" >&2; exit 1 ;;
esac
case "$UNAME_M" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "fetch-luxcpp.sh: unsupported arch $UNAME_M" >&2; exit 1 ;;
esac

# Target: ${SRCDIR}/../../../../luxcpp — the path cgo expects.
TARGET="$(cd "$SCRIPT_DIR/../../../.." && pwd)/luxcpp"
HEADERS="$TARGET/cevm/lib/evm/gpu/go_bridge.h"
LIB="$TARGET/cevm/build/lib/libevm.dylib"
[[ "$PLATFORM" == linux ]] && LIB="$TARGET/cevm/build/lib/libevm.so"

# Idempotent skip.
if [[ -z "${LUXCPP_FORCE:-}" && -f "$HEADERS" && -f "$LIB" ]]; then
  echo "fetch-luxcpp.sh: luxcpp $VERSION already present at $TARGET — skipping"
  exit 0
fi

ASSET="luxcpp-$VERSION-$PLATFORM-$ARCH.tar.gz"
URL="https://github.com/luxfi/luxcpp/releases/download/$VERSION/$ASSET"
SUMS_FILE="$SCRIPT_DIR/luxcpp-SHA256SUMS"

mkdir -p "$TARGET"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetch-luxcpp.sh: downloading $URL"
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSL -o "$TMP/$ASSET" "$URL"; then
    cat >&2 <<EOF
fetch-luxcpp.sh: download failed for $URL.
This usually means the luxcpp release tarball for $PLATFORM-$ARCH is not
yet published. Workarounds:
  1. Build from source: clone github.com/luxfi/luxcpp into $TARGET and
     run its CMake build (see luxcpp/cevm/README.md).
  2. Set LUXCPP_VERSION to a known-published tag.
EOF
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$TMP/$ASSET" "$URL"
else
  echo "fetch-luxcpp.sh: need curl or wget" >&2; exit 1
fi

# SHA-256 verify against pinned sums file. Missing entry = fail closed.
if [[ -f "$SUMS_FILE" ]]; then
  EXPECTED="$(awk -v a="$ASSET" '$2==a{print $1}' "$SUMS_FILE" || true)"
  if [[ -z "$EXPECTED" ]]; then
    echo "fetch-luxcpp.sh: no SHA-256 pinned for $ASSET in $SUMS_FILE — aborting" >&2
    exit 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    GOT="$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')"
  else
    GOT="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
  fi
  if [[ "$GOT" != "$EXPECTED" ]]; then
    echo "fetch-luxcpp.sh: SHA-256 mismatch for $ASSET" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  got:      $GOT" >&2
    exit 1
  fi
  echo "fetch-luxcpp.sh: SHA-256 OK ($GOT)"
else
  echo "fetch-luxcpp.sh: warning — no $SUMS_FILE; skipping checksum verification" >&2
fi

echo "fetch-luxcpp.sh: extracting into $TARGET"
tar -xzf "$TMP/$ASSET" -C "$TARGET" --strip-components=1
echo "fetch-luxcpp.sh: done"
