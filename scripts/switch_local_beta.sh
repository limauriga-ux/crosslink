#!/bin/sh
set -eu

VERSION="0.3.0-rc.2"
DMG_NAME="CrossLink-v${VERSION}-darwin-arm64.dmg"
DMG_SHA256="79e7ee55746b095700f8a050dcabb1961362fc669b34df5af8670e61b816abea"
REPOSITORY="limauriga-ux/crosslink"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
LOCAL_BUILD_DMG="$REPO_ROOT/dist/$DMG_NAME"

APP_PATH="/Applications/CrossLink.app"
DATA_DIR="$HOME/.crosslink"
STATE_ROOT="$HOME/.crosslink-beta-switch"
SERVICE_LABEL="io.github.limauriga.crosslink.daemon"
SERVICE_PLIST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
PRIVILEGED_HELPER="/Library/PrivilegedHelperTools/${SERVICE_LABEL}"
DAEMON_PROCESS_PATTERN='(^|/)(crosslink-daemon|io\.github\.limauriga\.crosslink\.daemon)( |$)'

YES=0
BACKUP_ARG=""
DMG_ARG=""
TMP_DIR=""
MOUNT_POINT=""
APP_STAGE=""
BACKUP_DIR=""

log() {
  printf '\n==> %s\n' "$*" >&2
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    printf 'backup retained at: %s\n' "$BACKUP_DIR" >&2
    printf 'rollback with: %s rollback --backup %s\n' "$0" "$BACKUP_DIR" >&2
  fi
  exit 1
}

cleanup() {
  if [ -n "$MOUNT_POINT" ] && [ -d "$MOUNT_POINT" ]; then
    hdiutil detach "$MOUNT_POINT" >/dev/null 2>&1 || true
  fi
  if [ -n "$APP_STAGE" ]; then
    sudo rm -rf "$APP_STAGE" >/dev/null 2>&1 || true
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

usage() {
  cat <<EOF
Usage:
  $0 install [--dmg PATH] [--yes]
  $0 rollback [--backup PATH] [--yes]
  $0 status

install
  Prefer dist/$DMG_NAME, or use --dmg PATH. If neither exists, download
  the release with an authenticated GitHub CLI. Verify the fixed SHA-256,
  stop the existing service, back up the app/data, replace the app, and
  launch the Beta. The Beta GUI installs its root-owned helper.

rollback
  Stop the Beta service, preserve current Beta data, restore the selected
  pre-Beta backup, restore the previous app, then launch it.

status
  Show the installed app version, service definition, helper metadata,
  running CrossLink processes, and latest backup path.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

confirm() {
  prompt="$1"
  if [ "$YES" -eq 1 ]; then
    return 0
  fi
  if [ ! -t 0 ]; then
    die "interactive confirmation unavailable; rerun with --yes"
  fi
  printf '%s [y/N] ' "$prompt" >&2
  read -r answer || exit 1
  case "$answer" in
    y|Y|yes|YES) ;;
    *) printf 'cancelled\n' >&2; exit 0 ;;
  esac
}

app_version() {
  app="$1"
  plist="$app/Contents/Info.plist"
  if [ ! -f "$plist" ]; then
    printf 'not installed\n'
    return
  fi
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist" 2>/dev/null || printf 'unknown\n'
}

validate_local_paths() {
  home_real="$(cd "$HOME" && pwd -P)"
  if [ -L "$STATE_ROOT" ]; then
    die "backup state root must not be a symlink: $STATE_ROOT"
  fi
  mkdir -p "$STATE_ROOT"
  state_real="$(cd "$STATE_ROOT" && pwd -P)"
  [ "$state_real" = "$home_real/.crosslink-beta-switch" ] || die "backup state root escaped HOME: $state_real"
  if [ -L "$DATA_DIR" ]; then
    die "CrossLink data root must not be a symlink: $DATA_DIR"
  fi
  if [ -L "$APP_PATH" ]; then
    die "CrossLink app path must not be a symlink: $APP_PATH"
  fi
}

wait_for_process_exit() {
  name="$1"
  count=0
  while pgrep -x "$name" >/dev/null 2>&1; do
    count=$((count + 1))
    if [ "$count" -ge 50 ]; then
      return 1
    fi
    sleep 0.1
  done
}

wait_for_daemon_exit() {
	count=0
	while pgrep -f "$DAEMON_PROCESS_PATTERN" >/dev/null 2>&1; do
		count=$((count + 1))
		if [ "$count" -ge 150 ]; then
			return 1
		fi
		sleep 0.1
	done
}

quit_app() {
  if ! pgrep -x crosslink-gui >/dev/null 2>&1; then
    return 0
  fi
  log "Quitting CrossLink GUI"
  osascript -e 'tell application id "io.github.limauriga.crosslink" to quit' >/dev/null 2>&1 || true
  wait_for_process_exit crosslink-gui || die "CrossLink GUI is still running; quit it manually and rerun"
}

stop_service() {
  log "Stopping CrossLink launch daemon"
  sudo launchctl bootout "system/${SERVICE_LABEL}" >/dev/null 2>&1 || true
  if ! wait_for_daemon_exit; then
    die "a CrossLink daemon process is still running; refusing to signal an unverified PID"
  fi
  sudo rm -f "$SERVICE_PLIST" "$PRIVILEGED_HELPER"
  sudo rm -f "$DATA_DIR/daemon.sock" "$DATA_DIR/crosslink.pid" 2>/dev/null || true
}

verify_app_bundle() {
  app="$1"
  [ -d "$app" ] || die "CrossLink.app missing from mounted DMG"
  version="$(app_version "$app")"
  [ "$version" = "$VERSION" ] || die "app version is $version, expected $VERSION"
  codesign --verify --deep --strict "$app" >/dev/null 2>&1 || die "app signature verification failed"
  file "$app/Contents/MacOS/crosslink-gui" | grep -q 'arm64' || die "app is not an arm64 executable"
  [ -f "$app/Contents/Resources/NOTICE" ] || die "packaged NOTICE is missing"
  grep -q '^go-pkcs12$' "$app/Contents/Resources/NOTICE" || die "packaged go-pkcs12 notice is missing"
}

create_backup() {
  timestamp="$(date +%Y%m%d-%H%M%S)"
  chmod 700 "$STATE_ROOT"
  BACKUP_DIR="$STATE_ROOT/$timestamp"
  mkdir -m 700 "$BACKUP_DIR"

  if [ -d "$DATA_DIR" ]; then
    log "Backing up $DATA_DIR"
    sudo ditto "$DATA_DIR" "$BACKUP_DIR/data"
  fi
  if [ -d "$APP_PATH" ]; then
    log "Backing up $APP_PATH"
    sudo ditto "$APP_PATH" "$BACKUP_DIR/CrossLink.app"
  fi

  cat > "$BACKUP_DIR/manifest" <<EOF
created_at=$timestamp
previous_app_version=$(app_version "$APP_PATH")
beta_version=$VERSION
EOF
  sudo chown -R "$(id -u):$(id -g)" "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  printf '%s\n' "$BACKUP_DIR" > "$STATE_ROOT/latest"
  chmod 600 "$STATE_ROOT/latest"
  log "Backup complete: $BACKUP_DIR"
}

replace_app() {
  source_app="$1"
  APP_STAGE="/Applications/.CrossLink.app.new.$$"
  sudo rm -rf "$APP_STAGE"
  sudo ditto "$source_app" "$APP_STAGE"
  verify_app_bundle "$APP_STAGE"
  sudo rm -rf "$APP_PATH"
  sudo mv "$APP_STAGE" "$APP_PATH"
  APP_STAGE=""
}

select_beta_dmg() {
  if [ -n "$DMG_ARG" ]; then
    [ -f "$DMG_ARG" ] || die "local DMG not found: $DMG_ARG"
    [ ! -L "$DMG_ARG" ] || die "local DMG must not be a symlink: $DMG_ARG"
    dmg="$DMG_ARG"
    log "Using local DMG: $dmg"
    return
  fi
  if [ -f "$LOCAL_BUILD_DMG" ] && [ ! -L "$LOCAL_BUILD_DMG" ]; then
    dmg="$LOCAL_BUILD_DMG"
    log "Using local build: $dmg"
    return
  fi
  need_cmd gh
  dmg="$TMP_DIR/$DMG_NAME"
  log "Local DMG not found; downloading $DMG_NAME"
  gh release download "v$VERSION" --repo "$REPOSITORY" --pattern "$DMG_NAME" --dir "$TMP_DIR" --clobber
}

install_beta() {
  for command in awk shasum hdiutil ditto codesign file grep pgrep osascript open sudo; do
    need_cmd "$command"
  done
  [ "$(uname -s)" = "Darwin" ] || die "this script supports macOS only"
  [ "$(uname -m)" = "arm64" ] || die "this Beta artifact supports Apple Silicon arm64 only"
  validate_local_paths

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/crosslink-beta.XXXXXX")"
  MOUNT_POINT="$TMP_DIR/mount"
  mkdir "$MOUNT_POINT"
  select_beta_dmg

  actual="$(shasum -a 256 "$dmg" | awk '{print $1}')"
  [ "$actual" = "$DMG_SHA256" ] || die "DMG SHA-256 mismatch: got $actual"

  log "Mounting and validating the Beta"
  hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT_POINT" "$dmg" >/dev/null
  verify_app_bundle "$MOUNT_POINT/CrossLink.app"

  current="$(app_version "$APP_PATH")"
  printf '\nInstalled version: %s\nBeta version:      %s\n' "$current" "$VERSION" >&2
  confirm "Stop CrossLink, back up its app/data, and install the Beta?"

  sudo -v
  quit_app
  stop_service
  create_backup
  replace_app "$MOUNT_POINT/CrossLink.app"

  log "Launching CrossLink v$VERSION"
  open "$APP_PATH"
  cat >&2 <<EOF

Installed CrossLink v$VERSION.
Backup: $BACKUP_DIR

The GUI should request administrator permission to install the new
root-owned helper. After it starts, verify daemon_version=$VERSION in the
Overview diagnostics. Roll back with:
  $0 rollback --backup "$BACKUP_DIR"
EOF
}

resolve_backup() {
  candidate="$BACKUP_ARG"
  if [ -z "$candidate" ]; then
    [ -f "$STATE_ROOT/latest" ] || die "no latest backup record at $STATE_ROOT/latest"
    candidate="$(sed -n '1p' "$STATE_ROOT/latest")"
  fi
  [ -d "$candidate" ] || die "backup directory not found: $candidate"
  state_real="$(cd "$STATE_ROOT" && pwd -P)"
  candidate_real="$(cd "$candidate" && pwd -P)"
  case "$candidate_real" in
    "$state_real"/*) ;;
    *) die "backup must be below $state_real" ;;
  esac
  [ -f "$candidate_real/manifest" ] || die "backup manifest missing: $candidate_real"
  BACKUP_DIR="$candidate_real"
}

restore_previous_app() {
  backup_app="$BACKUP_DIR/CrossLink.app"
  if [ ! -d "$backup_app" ]; then
    warn "backup contains no previous app; removing the Beta app"
    sudo rm -rf "$APP_PATH"
    return
  fi
  APP_STAGE="/Applications/.CrossLink.app.rollback.$$"
  sudo rm -rf "$APP_STAGE"
  sudo ditto "$backup_app" "$APP_STAGE"
  codesign --verify --deep --strict "$APP_STAGE" >/dev/null 2>&1 || die "backup app signature verification failed"
  sudo rm -rf "$APP_PATH"
  sudo mv "$APP_STAGE" "$APP_PATH"
  APP_STAGE=""
}

rollback_beta() {
  for command in ditto codesign pgrep osascript open sudo sed; do
    need_cmd "$command"
  done
  [ "$(uname -s)" = "Darwin" ] || die "this script supports macOS only"
  validate_local_paths
  resolve_backup

  previous="not installed"
  if [ -d "$BACKUP_DIR/CrossLink.app" ]; then
    previous="$(app_version "$BACKUP_DIR/CrossLink.app")"
  fi
  printf '\nCurrent version:  %s\nRestore version:  %s\nBackup:           %s\n' \
    "$(app_version "$APP_PATH")" "$previous" "$BACKUP_DIR" >&2
  confirm "Stop the Beta and restore this backup?"

  sudo -v
  quit_app
  stop_service

  timestamp="$(date +%Y%m%d-%H%M%S)"
  if [ -d "$DATA_DIR" ]; then
    preserved="$BACKUP_DIR/beta-data-$timestamp"
    log "Preserving current Beta data at $preserved"
    mv "$DATA_DIR" "$preserved"
  fi
  if [ -d "$BACKUP_DIR/data" ]; then
    log "Restoring pre-Beta data"
    ditto "$BACKUP_DIR/data" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
  fi
  restore_previous_app

  if [ -d "$APP_PATH" ]; then
    log "Launching restored CrossLink $(app_version "$APP_PATH")"
    open "$APP_PATH"
    printf '\nThe restored GUI will reinstall its matching system service.\n' >&2
  else
    printf '\nRollback complete; no previous app was present in the backup.\n' >&2
  fi
}

show_status() {
  printf 'Installed app version: %s\n' "$(app_version "$APP_PATH")"
  if [ -f "$SERVICE_PLIST" ]; then
    printf 'Launch daemon plist:   %s\n' "$SERVICE_PLIST"
    /usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$SERVICE_PLIST" 2>/dev/null || true
  else
    printf 'Launch daemon plist:   not installed\n'
  fi
  if [ -e "$PRIVILEGED_HELPER" ]; then
    stat -f 'Privileged helper:      %Su:%Sg %Sp %N' "$PRIVILEGED_HELPER"
  else
    printf 'Privileged helper:      not installed\n'
  fi
  if pgrep -fl "crosslink-gui|$DAEMON_PROCESS_PATTERN" 2>/dev/null; then
    :
  else
    printf 'CrossLink processes:    none\n'
  fi
  if [ -f "$STATE_ROOT/latest" ]; then
    printf 'Latest backup:          %s\n' "$(sed -n '1p' "$STATE_ROOT/latest")"
  else
    printf 'Latest backup:          none\n'
  fi
}

COMMAND="${1:-}"
[ "$#" -gt 0 ] && shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes)
      YES=1
      ;;
    --backup)
      shift
      [ "$#" -gt 0 ] || die "--backup requires a path"
      BACKUP_ARG="$1"
      ;;
    --dmg)
      shift
      [ "$#" -gt 0 ] || die "--dmg requires a path"
      DMG_ARG="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done
if [ -n "$DMG_ARG" ] && [ "$COMMAND" != "install" ]; then
  die "--dmg is valid only with install"
fi
if [ -n "$BACKUP_ARG" ] && [ "$COMMAND" != "rollback" ]; then
  die "--backup is valid only with rollback"
fi

case "$COMMAND" in
  install) install_beta ;;
  rollback) rollback_beta ;;
  status) show_status ;;
  -h|--help|help|"") usage ;;
  *) usage >&2; exit 2 ;;
esac
