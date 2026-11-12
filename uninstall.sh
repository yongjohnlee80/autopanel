#!/usr/bin/env sh
#
# AutoPanel uninstaller. install.sh puts a copy at /usr/local/sbin/autopanel-uninstall.
#
#   autopanel-uninstall --check            # list what would go; changes nothing (the default)
#   sudo autopanel-uninstall --apply       # remove the services and the binary; keep data, config and keys
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

UNIT_DIR=/etc/systemd/system
CORE_UNIT=$UNIT_DIR/autopanel-core.service
GATE_UNIT=$UNIT_DIR/autopanel-gate.service
OLD_UNIT=$UNIT_DIR/autopanel.service   # the one service of v0.1.4 and earlier
BIN=/usr/local/bin/autopanel
SELF=/usr/local/sbin/autopanel-uninstall
CONF_DIR=/etc/autopanel
STATE_DIR=/var/lib/autopanel
SVC_USER=autopanel
SERVICES_DIR=/var/lib/autopanel-services   # one directory per deployed service, each its user's home
BACKUP_DIR=/root

MODE=check
BACKUP=1
YES=0
KEEP_SERVICES=0

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
  --apply        Stop and remove the two services, the binary and this uninstaller.
                 Stops each deployed service. Keeps /var/lib/autopanel, /etc/autopanel
                 (with the keyfile), the user, and each service's user and directory,
                 so a reinstall picks up where it left off.
  --purge        --apply, plus the store, the configuration, the keyfile and the user,
                 and each deployed service's user and directory.

OPTIONS:
  --keep-services  Leave the deployed services as they are: running, with their users
                 and directories. They are then yours to stop and remove.
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
    --keep-services) KEEP_SERVICES=1; shift ;;
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

# service_names lists the deployed services: each directory under SERVICES_DIR
# whose user (ap-<name>) the host has. A directory kept from a removed service
# has no user, and is listed by --check as a directory only.
service_names() {
  [ -d "$SERVICES_DIR" ] || return 0
  for d in "$SERVICES_DIR"/*; do
    n=${d##*/}
    if [ -d "$d" ] && id "ap-$n" >/dev/null 2>&1; then
      printf '%s\n' "$n"
    fi
  done
}
SERVICES=$(service_names)

say "AutoPanel uninstall: $MODE"
say "Removed by --apply:"
for f in "$CORE_UNIT" "$GATE_UNIT" "$UNIT_DIR/autopanel-core.service.d" "$BIN" "$SELF"; do show "$f"; done
if exists "$OLD_UNIT"; then info "$OLD_UNIT (the one service of an earlier version)"; fi
say "Kept by --apply, removed by --purge:"
for f in "$STATE_DIR" "$CONF_DIR"; do show "$f"; done
if id "$SVC_USER" >/dev/null 2>&1; then info "system user $SVC_USER"; else info "system user $SVC_USER (absent)"; fi
[ "$engine" = postgres ] && info "NOT the PostgreSQL store: drop its schema yourself"
if [ -n "$SERVICES" ]; then
  if [ "$KEEP_SERVICES" -eq 1 ]; then
    say "Deployed services, left as they are (--keep-services):"
  else
    say "Deployed services, stopped by --apply; their users and directories removed by --purge:"
  fi
  for n in $SERVICES; do info "$n (user ap-$n, $SERVICES_DIR/$n)"; done
fi
if exists "$SERVICES_DIR" && [ "$KEEP_SERVICES" -eq 0 ]; then
  info "$SERVICES_DIR (removed by --purge)"
fi

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

# --- the deployed services -----------------------------------------------------

# Each runs under its own user's systemd, which runs without a login. --apply
# stops the unit and that systemd, so nothing AutoPanel started is left
# running; the user, its directory and its unit file stay, and a reinstalled
# AutoPanel starts the service again. --purge deletes the user and the
# directory.
if [ "$KEEP_SERVICES" -eq 0 ]; then
  for n in $SERVICES; do
    runuser -u "ap-$n" -- env XDG_RUNTIME_DIR="/run/user/$(id -u "ap-$n")" systemctl --user stop "$n.service" >/dev/null 2>&1 || true
    loginctl disable-linger "ap-$n" >/dev/null 2>&1 || true
    loginctl terminate-user "ap-$n" >/dev/null 2>&1 || true
    if [ "$MODE" = purge ]; then
      userdel "ap-$n" >/dev/null 2>&1 || userdel --force "ap-$n" >/dev/null 2>&1 \
        || info "could not remove user ap-$n; remove it by hand"
      info "removed the service $n and its user ap-$n"
    else
      info "stopped the service $n"
    fi
  done
  if [ "$MODE" = purge ] && exists "$SERVICES_DIR"; then
    rm -rf "$SERVICES_DIR"
    info "removed $SERVICES_DIR"
  fi
fi

# --- the services, the binary --------------------------------------------------

# The gate first, then the core that runs it; then the one service of an
# earlier version, if it is still here.
systemctl stop autopanel-gate >/dev/null 2>&1 || true
systemctl disable --now autopanel-core >/dev/null 2>&1 || true
systemctl disable --now autopanel >/dev/null 2>&1 || true
rm -f "$CORE_UNIT" "$GATE_UNIT" "$OLD_UNIT"
rm -rf "$UNIT_DIR/autopanel-core.service.d" "$UNIT_DIR/autopanel.service.d"
systemctl daemon-reload
rm -f "$BIN" "$BIN.previous"
info "removed the services and $BIN"

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
