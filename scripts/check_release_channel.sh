#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="${1:-${VERSION:-dev}}"
VERSION="$(printf '%s' "$VERSION" | tr -d '[:space:]' | sed 's/^v//')"

case "$VERSION" in
  dev|*-*) exit 0 ;;
esac

MODULES='github.com/sagernet/sing github.com/sagernet/sing-tun github.com/sagernet/sing-quic github.com/sagernet/sing-openvpn'
DEPENDENCIES="$(cd "$ROOT_DIR" && go list -m -f '{{.Path}} {{.Version}}' $MODULES)"
UNSTABLE="$(printf '%s\n' "$DEPENDENCIES" | sed -n '/ v[^ ]*-/p')"
if [ -n "$UNSTABLE" ]; then
  printf 'error: stable version %s is blocked by prerelease networking dependencies:\n%s\n' "$VERSION" "$UNSTABLE" >&2
  printf 'use a prerelease version such as %s-beta.1, or move to stable dependency releases first\n' "$VERSION" >&2
  exit 1
fi
