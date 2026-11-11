#!/usr/bin/env sh
#
# AutoPanel installer. Run as root on the server, from the unpacked release
# (make dist): autopanel, install.sh, uninstall.sh, autopanel.service and
# autopanel.env.example side by side.
#
#   sudo ./install.sh --email admin@example.com              # first install: asks for the master passphrase
#   sudo ./install.sh                                        # upgrade: replaces the binary, keeps everything else
#
# What it does, in order:
#   1. creates the system user "autopanel" (no login shell, no home);
#   2. installs /usr/local/bin/autopanel and the systemd unit;
#   3. creates /etc/autopanel (root:autopanel 0750) with autopanel.env, and
#      /etc/autopanel/keyslot (autopanel 0700) for the service keyfile;
#   4. on first install, asks twice for the master passphrase and runs
#      `autopanel --init`, which makes the root user, the master key and the
#      keyfile that lets the service unlock it after a reboot;
#   5. installs this release's uninstaller as /usr/local/sbin/autopanel-uninstall;
#   6. enables and (re)starts the service.
#
# The master passphrase is root's login for the admin TUI and the only way to
# open the store's secrets without the keyfile. It is read from the terminal
# with echo off, passed to --init on stdin, and never written anywhere.
# Losing both it and the keyfile loses every sealed secret.

set -eu

PREFIX_BIN=/usr/local/bin
UNINSTALLER=/usr/local/sbin/autopanel-uninstall
UNIT=/etc/systemd/system/autopanel.service
CONF_DIR=/etc/autopanel
ENV_FILE=$CONF_DIR/autopanel.env
KEY_DIR=$CONF_DIR/keyslot
KEYFILE=$KEY_DIR/service.key
STATE_DIR=/var/lib/autopanel
SVC_USER=autopanel

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
BINARY=$HERE/autopanel
EMAIL=""
CA=""
HTTP_ADDR=":80"
HTTPS_ADDR=":443"
ROOT_USER=root
PASSFILE=""
START=1
RESTART=always

say()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
AutoPanel installer

USAGE:
  sudo ./install.sh [OPTIONS]

OPTIONS:
  --binary <path>          The autopanel binary. Default: ./autopanel beside this script
  --email <address>        ACME account contact (required on first install)
  --ca staging|production  Let's Encrypt directory. Default: staging (first install only)
  --http <addr>            The gate's plain listener. Default: :80
  --https <addr>           The gate's TLS listener. Default: :443
  --user <name>            The panel's first user. Default: root
  --passphrase-file <path> Read the master passphrase from a 0600 file instead of the terminal
  --restart <policy>       always (default): restart after any exit, and start at boot
                           on-failure: only after a crash;  no: never restart on its own
  --no-start               Install and initialize, but don't start the service
  -h, --help               This text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY=${2:?}; shift 2 ;;
    --email) EMAIL=${2:?}; shift 2 ;;
    --ca) CA=${2:?}; shift 2 ;;
    --http) HTTP_ADDR=${2:?}; shift 2 ;;
    --https) HTTPS_ADDR=${2:?}; shift 2 ;;
    --user) ROOT_USER=${2:?}; shift 2 ;;
    --passphrase-file) PASSFILE=${2:?}; shift 2 ;;
    --restart) RESTART=${2:?}; shift 2 ;;
    --no-start) START=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

# --- preflight -------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
[ "$(uname -s)" = Linux ] || die "AutoPanel installs on Linux with systemd"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"
[ -f "$BINARY" ] || die "no binary at $BINARY (use --binary)"
[ -f "$HERE/autopanel.service" ] || die "autopanel.service is missing beside install.sh"
[ -f "$HERE/uninstall.sh" ] || die "uninstall.sh is missing beside install.sh"
case "$CA" in ""|staging|production) ;; *) die "--ca is staging or production" ;; esac
case "$RESTART" in always|on-failure|no) ;; *) die "--restart is always, on-failure or no" ;; esac
VERSION=$("$BINARY" --version 2>/dev/null) || die "$BINARY does not run on this host"
say "Installing $VERSION"

# --- 1. the service user -----------------------------------------------------

if id "$SVC_USER" >/dev/null 2>&1; then
  info "user $SVC_USER exists"
else
  useradd --system --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  info "created system user $SVC_USER"
fi

# --- 2. the binary and the unit ----------------------------------------------

install -m 0755 "$BINARY" "$PREFIX_BIN/autopanel"
install -m 0644 "$HERE/autopanel.service" "$UNIT"
DROPIN=/etc/systemd/system/autopanel.service.d/restart.conf
if [ "$RESTART" = always ]; then
  rm -f "$DROPIN"
else
  install -d -m 0755 "$(dirname "$DROPIN")"
  printf '[Service]\nRestart=%s\n' "$RESTART" > "$DROPIN"
  info "restart policy: $RESTART ($DROPIN)"
fi
systemctl daemon-reload
info "installed $PREFIX_BIN/autopanel and $UNIT"

# --- 3. configuration and key directories ------------------------------------

install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$KEY_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
if [ -f "$ENV_FILE" ]; then
  info "kept $ENV_FILE"
  [ -z "$EMAIL$CA" ] || info "(--email and --ca apply only to a first install; edit $ENV_FILE to change them)"
else
  [ -n "$EMAIL" ] || die "--email is required on a first install (the ACME account's contact)"
  case "$EMAIL" in *@*.*) ;; *) die "--email $EMAIL is not an address" ;; esac
  umask 027
  {
    printf '# Written by install.sh. root:%s 0640. Holds no secrets: the Cloudflare\n' "$SVC_USER"
    printf '# token is set with certs.cloudflare.set and kept sealed in the store.\n'
    printf 'AUTOPANEL_HTTP_ADDR=%s\n' "$HTTP_ADDR"
    printf 'AUTOPANEL_HTTPS_ADDR=%s\n' "$HTTPS_ADDR"
    printf 'AUTOPANEL_ACME_CA=%s\n' "${CA:-staging}"
    printf 'AUTOPANEL_ACME_EMAIL=%s\n' "$EMAIL"
    printf 'AUTOPANEL_KEYFILE=%s\n' "$KEYFILE"
    printf '#AUTOPANEL_TRUSTED_PROXIES=\n'
  } > "$ENV_FILE"
  chown root:"$SVC_USER" "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
  info "wrote $ENV_FILE"
fi

# --- 4. the root user and the master key -------------------------------------

as_service() {
  # The service's own environment, as the service user: the same paths --serve uses.
  runuser -u "$SVC_USER" -- sh -c "set -a; . '$ENV_FILE'; set +a; exec \"\$@\"" autopanel "$@"
}

read_passphrase() {
  if [ -n "$PASSFILE" ]; then
    [ -f "$PASSFILE" ] || die "no passphrase file at $PASSFILE"
    case "$(stat -c %a "$PASSFILE")" in 600|400) ;; *) die "$PASSFILE must be mode 0600" ;; esac
    head -n 1 "$PASSFILE"
    return
  fi
  [ -r /dev/tty ] || die "the master passphrase needs a terminal (or --passphrase-file)"
  old=$(stty -g </dev/tty)
  trap 'stty "$old" </dev/tty' EXIT INT TERM
  printf 'Master passphrase for %s (at least 12 characters): ' "$ROOT_USER" >/dev/tty
  stty -echo </dev/tty; IFS= read -r p1 </dev/tty; stty "$old" </dev/tty; printf '\n' >/dev/tty
  printf 'Again: ' >/dev/tty
  stty -echo </dev/tty; IFS= read -r p2 </dev/tty; stty "$old" </dev/tty; printf '\n' >/dev/tty
  trap - EXIT INT TERM
  [ "$p1" = "$p2" ] || die "the passphrases differ"
  printf '%s\n' "$p1"
}

if [ -f "$KEYFILE" ]; then
  info "already initialized (keyfile $KEYFILE exists)"
else
  say "Creating the panel's $ROOT_USER user and master key"
  read_passphrase | as_service "$PREFIX_BIN/autopanel" --init --user "$ROOT_USER" \
    || die "initialization failed; nothing was started"
fi

# --- 5. the uninstaller ------------------------------------------------------

install -d -m 0755 "$(dirname "$UNINSTALLER")"
install -m 0755 "$HERE/uninstall.sh" "$UNINSTALLER"
info "installed $UNINSTALLER"

# --- 6. the service ----------------------------------------------------------

systemctl enable autopanel >/dev/null 2>&1
if [ "$START" -eq 1 ]; then
  systemctl restart autopanel
  i=0
  while [ $i -lt 20 ] && [ ! -S /run/autopanel/control.sock ]; do sleep 0.5; i=$((i + 1)); done
  if systemctl is-active --quiet autopanel && [ -S /run/autopanel/control.sock ]; then
    info "autopanel is running"
  else
    systemctl --no-pager status autopanel || true
    die "autopanel did not start; see journalctl -u autopanel"
  fi
fi

say ""
say "Done. Next:"
info "point a name's DNS at this host, then:  sudo -u $SVC_USER autopanel --ui"
info "log in as $ROOT_USER with the master passphrase; add a route with 'a'"
info "staging certificates first; switch AUTOPANEL_ACME_CA=production in $ENV_FILE and restart when they work"
info "behind Cloudflare's proxy: sudo -u $SVC_USER autopanel --call certs.cloudflare.set '{\"token\":\"…\"}'"
info "remove: sudo autopanel-uninstall --check"
