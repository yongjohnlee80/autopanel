#!/usr/bin/env sh
#
# AutoPanel uninstaller. install.sh puts a copy at /usr/local/sbin/autopanel-uninstall.
#
#   autopanel-uninstall --check            # list what would go; changes nothing (the default)
#   sudo autopanel-uninstall --apply       # remove the service and the binary; keep data, config and keys
#   sudo autopanel-uninstall --purge       # also the store, the config, the keyfile and the user
#
# WHAT IS UNRECOVERABLE, said before anything else. The store holds the routes,
# the audit log, the users and every SEALED SECRET: certificate and ACME
# private keys, the Cloudflare token. Without the master key they are useless,
# and the master key opens only with the master passphrase or the keyfile.
# --purge therefore takes a backup of the store first, by default.
#
# THE BACKUP DOES NOT INCLUDE THE KEYFILE, deliberately: an archive holding the
# store and the keyfile together is both halves of one envelope, a credential
# rather than a backup. To restore, you need the master passphrase.
#
# A PostgreSQL store (AUTOPANEL_STORE_ENGINE=postgres) lives in its database:
# --purge doesn't touch it, and says so.

set -eu

UNIT=/etc/systemd/system/autopanel.service
BIN=/usr/local/bin/autopanel
SELF=/usr/local/sbin/autopanel-uninstall
CONF_DIR=/etc/autopanel
STATE_DIR=/var/lib/autopanel
SVC_USER=autopanel
BACKUP_DIR=/root

MODE=check
BACKUP=1
YES=0

say()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
AutoPanel uninstaller

USAGE:
  autopanel-uninstall [--check | --apply | --purge] [OPTIONS]

MODES:
  --check        List what would be removed. Changes nothing. (default)
  --apply        Stop and remove the service, the binary and this uninstaller.
                 Keeps /var/lib/autopanel, /etc/autopanel (with the keyfile) and the user,
                 so a reinstall picks up where it left off.
  --purge        --apply, plus the store, the configuration, the keyfile and the user.

OPTIONS:
  --no-backup    With --purge: don't back the store up first.
  --backup-dir   Where --purge writes its backup. Default: /root
  --yes          Don't ask to confirm --purge.
  -h, --help     This text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check; shift ;;
    --apply) MODE=apply; shift ;;
    --purge) MODE=purge; shift ;;
    --no-backup) BACKUP=0; shift ;;
    --backup-dir) BACKUP_DIR=${2:?}; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

exists() { [ -e "$1" ] || [ -L "$1" ]; }
show() { if exists "$1"; then info "$1"; else info "$1 (absent)"; fi; }

engine=sqlite
if [ -r "$CONF_DIR/autopanel.env" ] && grep -q '^AUTOPANEL_STORE_ENGINE=postgres' "$CONF_DIR/autopanel.env" 2>/dev/null; then
  engine=postgres
fi

say "AutoPanel uninstall: $MODE"
say "Removed by --apply:"
for f in "$UNIT" /etc/systemd/system/autopanel.service.d "$BIN" "$SELF"; do show "$f"; done
say "Kept by --apply, removed by --purge:"
for f in "$STATE_DIR" "$CONF_DIR"; do show "$f"; done
if id "$SVC_USER" >/dev/null 2>&1; then info "system user $SVC_USER"; else info "system user $SVC_USER (absent)"; fi
[ "$engine" = postgres ] && info "NOT the PostgreSQL store: drop its schema yourself"

[ "$MODE" = check ] && exit 0
[ "$(id -u)" -eq 0 ] || die "run as root"

if [ "$MODE" = purge ] && [ "$YES" -eq 0 ]; then
  # Open the terminal rather than test the node: /dev/tty is readable by mode
  # even when the process has no controlling terminal.
  ( : <>/dev/tty ) 2>/dev/null || die "--purge needs a terminal to confirm, or --yes"
  printf 'This destroys the store and the keyfile. Type "purge" to go on: ' >/dev/tty
  IFS= read -r answer </dev/tty
  [ "$answer" = purge ] || die "not confirmed; nothing was removed"
fi

# --- the service, the binary --------------------------------------------------

if systemctl list-unit-files autopanel.service >/dev/null 2>&1; then
  systemctl disable --now autopanel >/dev/null 2>&1 || true
fi
rm -f "$UNIT"
rm -rf /etc/systemd/system/autopanel.service.d
systemctl daemon-reload
rm -f "$BIN"
info "removed the service and $BIN"

# --- data, configuration, keys, user (--purge) ---------------------------------

if [ "$MODE" = purge ]; then
  if [ "$BACKUP" -eq 1 ] && [ -d "$STATE_DIR" ] && [ "$engine" = sqlite ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    out="$BACKUP_DIR/autopanel-store-$ts.tar.gz"
    umask 077
    tar -C "$(dirname "$STATE_DIR")" -czf "$out" "$(basename "$STATE_DIR")"
    info "backed up the store to $out (0600; no keyfile: restoring needs the master passphrase)"
  fi
  rm -rf "$STATE_DIR" "$CONF_DIR"
  info "removed $STATE_DIR and $CONF_DIR (the keyfile with it)"
  if id "$SVC_USER" >/dev/null 2>&1; then
    userdel "$SVC_USER" 2>/dev/null || info "could not remove user $SVC_USER; remove it by hand"
    info "removed system user $SVC_USER"
  fi
fi

# Last: this script, which may be the copy that is running.
rm -f "$SELF"
say "Done."
