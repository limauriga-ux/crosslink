#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"
APP_NAME="${APP_NAME:-CrossLink}"
APP_BIN="${APP_BIN:-crosslink-gui}"
BUNDLE_ID="${BUNDLE_ID:-io.github.limauriga.crosslink}"
LOGO_PATH="${LOGO_PATH:-$ROOT_DIR/packaging/logo.png}"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build/package"
VOL_NAME="${VOL_NAME:-$APP_NAME}"
WAILS_BIN="${WAILS:-}"
SINGBOX_TAGS="${SINGBOX_TAGS:-with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls,badlinkname,tfogo_checklinkname0}"
SINGBOX_LDFLAGS="${SINGBOX_LDFLAGS:--checklinkname=0}"

SKIP_BUILD=0
SKIP_TESTS=0
CLEAN=0
DOCTOR=0
TARGET="${TARGET:-}"
ARCH="${ARCH:-}"

log() {
  printf '\n==> %s\n' "$*" >&2
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

host_target() {
  case "$(uname -s)" in
    Darwin) printf 'darwin\n' ;;
    Linux) printf 'linux\n' ;;
    MINGW*|MSYS*|CYGWIN*) printf 'windows\n' ;;
    *)
      printf 'error: unsupported host OS: %s\n' "$(uname -s)" >&2
      exit 1
      ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    i386|i686) printf '386\n' ;;
    armv7*|armv6*) printf 'arm\n' ;;
    *)
      printf 'error: unsupported host arch: %s\n' "$(uname -m)" >&2
      exit 1
      ;;
  esac
}

is_native_target() {
  [ "$TARGET" = "$(host_target)" ] && [ "$ARCH" = "$(host_arch)" ]
}

run_tests_directly() {
  is_native_target && [ "$TARGET" != "windows" ]
}

resolve_version() {
  if [ "${VERSION+x}" = "x" ] && [ -n "$(printf '%s' "$VERSION" | tr -d '[:space:]')" ]; then
    printf '%s\n' "$(printf '%s' "$VERSION" | tr -d '[:space:]' | sed 's/^v//')"
    return
  fi

  if [ "${GITHUB_REF_TYPE:-}" = "tag" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
    printf '%s\n' "$(printf '%s' "$GITHUB_REF_NAME" | sed 's/^v//')"
    return
  fi

  printf 'dev\n'
}

resolve_wails() {
  if [ -n "$WAILS_BIN" ]; then
    if [ ! -x "$WAILS_BIN" ] && ! command -v "$WAILS_BIN" >/dev/null 2>&1; then
      printf 'error: WAILS=%s is not executable or on PATH\n' "$WAILS_BIN" >&2
      exit 1
    fi
    printf '%s\n' "$WAILS_BIN"
    return
  fi

  if command -v wails3 >/dev/null 2>&1; then
    command -v wails3
    return
  fi

  GOPATH_VALUE="$(go env GOPATH)"
  GOEXE_VALUE="$(go env GOEXE 2>/dev/null || true)"
  CANDIDATE="$GOPATH_VALUE/bin/wails3$GOEXE_VALUE"
  if [ "$(host_target)" = "windows" ] && command -v cygpath >/dev/null 2>&1; then
    CANDIDATE="$(cygpath -u "$CANDIDATE")"
  fi
  if [ -x "$CANDIDATE" ]; then
    printf '%s\n' "$CANDIDATE"
    return
  fi

  WAILS_VERSION="$(cd "$ROOT_DIR" && go list -m -f '{{.Version}}' github.com/wailsapp/wails/v3 2>/dev/null || printf 'latest')"
  log "Installing Wails v3 CLI ($WAILS_VERSION)"
  go install "github.com/wailsapp/wails/v3/cmd/wails3@$WAILS_VERSION"
  if [ ! -x "$CANDIDATE" ]; then
    printf 'error: installed wails3 but cannot find %s\n' "$CANDIDATE" >&2
    exit 1
  fi
  printf '%s\n' "$CANDIDATE"
}

cross_test_packages() {
  (cd "$ROOT_DIR" && go list ./... | sed '/\/cmd\/gui$/d')
}

usage() {
  cat <<EOF
Usage: scripts/build_wails.sh [--target darwin|linux|windows] [--arch amd64|arm64|386|arm] [--skip-build] [--skip-tests] [--clean] [--doctor] [--logo /path/logo.png]

Environment:
  APP_NAME=CrossLink
  APP_BIN=crosslink-gui
  BUNDLE_ID=io.github.limauriga.crosslink
  VERSION=<release version; defaults to GitHub tag, then dev>
  TARGET=<target OS; defaults to host OS>
  ARCH=<target arch; defaults to host arch>
  WAILS=/path/to/wails3
  LOGO_PATH=packaging/logo.png
  VOL_NAME=CrossLink

Output:
  macOS:   dist/\$APP_NAME-v<version>-darwin-amd64.dmg
           dist/\$APP_NAME-v<version>-darwin-arm64.dmg
  Linux:   dist/\$APP_NAME-v<version>-linux-amd64.tar.gz
  Windows: dist/\$APP_NAME-v<version>-windows-amd64.zip
EOF
}

zip_dir() {
  source_dir="$1"
  output_file="$2"

  if command -v zip >/dev/null 2>&1; then
    (cd "$source_dir" && zip -qr "$output_file" .)
    return
  fi

  if command -v 7z >/dev/null 2>&1; then
    (cd "$source_dir" && 7z a -tzip "$output_file" . >/dev/null)
    return
  fi

  if command -v powershell.exe >/dev/null 2>&1; then
    win_source="$(cd "$source_dir" && pwd -W)"
    win_output="$(cd "$(dirname "$output_file")" && pwd -W)/$(basename "$output_file")"
    powershell.exe -NoProfile -Command "Compress-Archive -Path '${win_source}\\*' -DestinationPath '${win_output}' -Force"
    return
  fi

  printf 'error: zip, 7z, or powershell.exe is required to create %s\n' "$output_file" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      shift
      [ "$#" -gt 0 ] || { printf 'error: --target requires a value\n' >&2; exit 1; }
      TARGET="$1"
      ;;
    --arch)
      shift
      [ "$#" -gt 0 ] || { printf 'error: --arch requires a value\n' >&2; exit 1; }
      ARCH="$1"
      ;;
    --skip-build)
      SKIP_BUILD=1
      ;;
    --skip-tests)
      SKIP_TESTS=1
      ;;
    --clean)
      CLEAN=1
      ;;
    --doctor)
      DOCTOR=1
      ;;
    --logo)
      shift
      [ "$#" -gt 0 ] || { printf 'error: --logo requires a path\n' >&2; exit 1; }
      LOGO_PATH="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

need_cmd go
need_cmd npm

TARGET="${TARGET:-$(host_target)}"
ARCH="${ARCH:-$(host_arch)}"
VERSION="$(resolve_version)"
"$ROOT_DIR/scripts/check_release_channel.sh" "$VERSION"

case "$TARGET" in
  darwin|linux|windows) ;;
  *) printf 'error: unsupported target: %s\n' "$TARGET" >&2; exit 1 ;;
esac

case "$ARCH" in
  amd64|arm64|386|arm) ;;
  *) printf 'error: unsupported arch: %s\n' "$ARCH" >&2; exit 1 ;;
esac

case "$TARGET/$ARCH" in
  darwin/amd64|darwin/arm64|linux/amd64|windows/amd64) ;;
  *)
    printf 'error: unsupported release target: %s/%s\n' "$TARGET" "$ARCH" >&2
    printf 'supported targets: darwin/amd64, darwin/arm64, linux/amd64, windows/amd64\n' >&2
    exit 1
    ;;
esac

ARTIFACT_BASENAME="$APP_NAME-v$VERSION-$TARGET-$ARCH"
STAGING_DIR="$BUILD_DIR/$ARTIFACT_BASENAME"
BINARY_NAME="$APP_BIN"
[ "$TARGET" = "windows" ] && BINARY_NAME="$APP_BIN.exe"

WAILS_BIN="$(resolve_wails)"
log "Using Wails: $WAILS_BIN"
"$WAILS_BIN" version >/dev/null

if [ "$DOCTOR" -eq 1 ]; then
  log "Running Wails doctor"
  "$WAILS_BIN" doctor
fi

if [ "$CLEAN" -eq 1 ]; then
  log "Cleaning generated outputs"
  rm -rf "$ROOT_DIR/bin" "$ROOT_DIR/cmd/gui/assets" "$ROOT_DIR/cmd/gui/daemon" "$BUILD_DIR" "$DIST_DIR"
  mkdir -p "$ROOT_DIR/cmd/gui/assets"
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  log "Installing frontend dependencies"
  if [ -f "$FRONTEND_DIR/package-lock.json" ]; then
    (cd "$FRONTEND_DIR" && npm ci)
  else
    (cd "$FRONTEND_DIR" && npm install)
  fi

  log "Building Wails GUI for $TARGET/$ARCH"
  (cd "$ROOT_DIR" && GOOS="$TARGET" GOARCH="$ARCH" VERSION="$VERSION" WAILS="$WAILS_BIN" APP_BIN="$APP_BIN" "$WAILS_BIN" build)

  if [ "$SKIP_TESTS" -eq 0 ]; then
    log "Running Go tests"
    if run_tests_directly; then
	  (cd "$ROOT_DIR" && GOOS="$TARGET" GOARCH="$ARCH" go test -tags "$SINGBOX_TAGS" -ldflags "$SINGBOX_LDFLAGS" ./...)
    else
      TEST_PACKAGES="$(cross_test_packages)"
	  (cd "$ROOT_DIR" && GOOS="$TARGET" GOARCH="$ARCH" go test -tags "$SINGBOX_TAGS" -ldflags "$SINGBOX_LDFLAGS" -exec=true $TEST_PACKAGES)
    fi

    log "Running Go vet"
    if run_tests_directly; then
	  (cd "$ROOT_DIR" && GOOS="$TARGET" GOARCH="$ARCH" go vet -tags "$SINGBOX_TAGS" ./...)
    else
      TEST_PACKAGES="$(cross_test_packages)"
	  (cd "$ROOT_DIR" && GOOS="$TARGET" GOARCH="$ARCH" go vet -tags "$SINGBOX_TAGS" $TEST_PACKAGES)
    fi
  fi
fi

if [ ! -f "$ROOT_DIR/bin/$BINARY_NAME" ]; then
  printf 'error: app binary not found: %s\n' "$ROOT_DIR/bin/$BINARY_NAME" >&2
  exit 1
fi

rm -rf "$BUILD_DIR" "$DIST_DIR/$ARTIFACT_BASENAME".* "$DIST_DIR/$APP_NAME.app"
mkdir -p "$STAGING_DIR" "$DIST_DIR"

case "$TARGET" in
  darwin)
    need_cmd sips
    need_cmd iconutil
    need_cmd hdiutil

    [ -f "$LOGO_PATH" ] || { printf 'error: logo not found: %s\n' "$LOGO_PATH" >&2; exit 1; }

    ICONSET_DIR="$BUILD_DIR/icon.iconset"
    APP_DIR="$STAGING_DIR/$APP_NAME.app"

    log "Preparing temporary app bundle"
    mkdir -p "$ICONSET_DIR" "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

    for size in 16 32 128 256 512; do
      sips -s format png -z "$size" "$size" "$LOGO_PATH" --out "$ICONSET_DIR/icon_${size}x${size}.png" >/dev/null
    done
    for size in 16 32 128 256 512; do
      double=$((size * 2))
      sips -s format png -z "$double" "$double" "$LOGO_PATH" --out "$ICONSET_DIR/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns "$ICONSET_DIR" -o "$APP_DIR/Contents/Resources/AppIcon.icns"

    install -m 0755 "$ROOT_DIR/bin/$BINARY_NAME" "$APP_DIR/Contents/MacOS/$APP_BIN"
    install -m 0644 "$ROOT_DIR/LICENSE" "$APP_DIR/Contents/Resources/LICENSE"
    install -m 0644 "$ROOT_DIR/NOTICE" "$APP_DIR/Contents/Resources/NOTICE"
    cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>zh_CN</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$APP_BIN</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF
    printf 'APPL????' > "$APP_DIR/Contents/PkgInfo"

    xattr -cr "$APP_DIR" 2>/dev/null || true
    if command -v codesign >/dev/null 2>&1; then
      log "Ad-hoc signing app bundle"
      if ! codesign --force --deep --sign - "$APP_DIR"; then
        printf 'warning: ad-hoc signing failed; continuing without signature\n' >&2
      fi
    fi

    ARTIFACT_PATH="$DIST_DIR/$ARTIFACT_BASENAME.dmg"
    log "Creating DMG"
    ln -s /Applications "$STAGING_DIR/Applications"
    hdiutil create -volname "$VOL_NAME" -srcfolder "$STAGING_DIR" -ov -format UDZO "$ARTIFACT_PATH"
    ;;

  linux)
    ARTIFACT_PATH="$DIST_DIR/$ARTIFACT_BASENAME.tar.gz"
    install -m 0755 "$ROOT_DIR/bin/$BINARY_NAME" "$STAGING_DIR/$BINARY_NAME"
    install -m 0644 "$ROOT_DIR/README.md" "$STAGING_DIR/README.md"
    install -m 0644 "$ROOT_DIR/LICENSE" "$STAGING_DIR/LICENSE"
    install -m 0644 "$ROOT_DIR/NOTICE" "$STAGING_DIR/NOTICE"
    log "Creating tar.gz"
    tar -czf "$ARTIFACT_PATH" -C "$BUILD_DIR" "$ARTIFACT_BASENAME"
    ;;

  windows)
    ARTIFACT_PATH="$DIST_DIR/$ARTIFACT_BASENAME.zip"
    install -m 0755 "$ROOT_DIR/bin/$BINARY_NAME" "$STAGING_DIR/$BINARY_NAME"
    install -m 0644 "$ROOT_DIR/README.md" "$STAGING_DIR/README.md"
    install -m 0644 "$ROOT_DIR/LICENSE" "$STAGING_DIR/LICENSE"
    install -m 0644 "$ROOT_DIR/NOTICE" "$STAGING_DIR/NOTICE"
    log "Creating zip"
    zip_dir "$STAGING_DIR" "$ARTIFACT_PATH"
    ;;
esac

rm -rf "$BUILD_DIR" "$ROOT_DIR/bin/$BINARY_NAME"
rmdir "$ROOT_DIR/bin" "$ROOT_DIR/build" 2>/dev/null || true

log "Artifact complete"
printf '%s\n' "$ARTIFACT_PATH"
