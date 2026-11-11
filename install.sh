#!/usr/bin/env sh
#
# AutoPanel installer. Run as root on the server.
#
#   sudo ./install.sh                                        # first install: asks for the contact email, staging or
#                                                            # production certificates, and the master passphrase
#   sudo ./install.sh --email admin@example.com              # the same, with the email given
#   sudo ./install.sh                                        # upgrade: replaces the binary, keeps everything else
#
# Where the binary comes from, in this order:
#   a. --binary <path>, or an unpacked release (make dist) with autopanel,
#      uninstall.sh and autopanel.service beside this script;
#   b. the release tarball for this machine from GitHub: the latest release, or
#      the one --version names. Its published SHA-256 is checked, and a
#      mismatch stops the install;
#   c. when no release can be downloaded, a build from source on this host
#      (git and Go 1.26 or later): the tag, or main when there is no release yet.
#      --source goes straight here.
# All of that happens in a temporary directory, before anything on the host is
# changed.
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

REPO=yongjohnlee80/autopanel
MIN_GO_MAJOR=1
MIN_GO_MINOR=26

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
BINARY=""         # --binary; otherwise found beside this script, downloaded or built
FILES=""          # the directory holding autopanel.service and uninstall.sh
RELEASE=latest    # --version
FROM=auto         # auto | source
WANT_VERSION=""   # what a downloaded or built binary must report
TMP=""
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
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required $2"; }

usage() {
  cat <<'USAGE'
AutoPanel installer

USAGE:
  sudo ./install.sh [OPTIONS]

OPTIONS:
  --binary <path>          Use this autopanel binary (uninstall.sh and autopanel.service beside this script)
  --version <tag>          The release to download or build (e.g. v0.1.0). Default: latest
  --source                 Build from source on this host instead of downloading a release
  --email <address>        ACME account contact. A first install asks for it when it is not given
  --ca staging|production  Which Let's Encrypt service issues the certificates. A first install
                           asks when it is not given (staging with no terminal to ask on).
                           staging: test certificates browsers do not trust, loose limits.
                           production: real certificates, strict limits.
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
    --version) RELEASE=${2:?}; shift 2 ;;
    --source) FROM=source; shift ;;
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
case "$RELEASE" in latest|v[0-9]*) ;; *) die "--version is a release tag such as v0.1.0" ;; esac
case "$RELEASE" in *[!A-Za-z0-9._-]*) die "--version is a release tag such as v0.1.0" ;; esac
[ -z "$BINARY" ] || [ "$FROM$RELEASE" = autolatest ] || die "--binary can't be combined with --version or --source"
case "$CA" in ""|staging|production) ;; *) die "--ca is staging or production" ;; esac
case "$RESTART" in always|on-failure|no) ;; *) die "--restart is always, on-failure or no" ;; esac

# What a first install needs is checked here, before anything is changed: a
# refused install leaves the host as it was.
# have_tty opens the terminal rather than testing the node: /dev/tty is
# readable by mode even when the process has no controlling terminal.
have_tty() { ( : <>/dev/tty ) 2>/dev/null; }
# valid_email admits only what an address needs: the value is written to the
# service's environment file, so no spaces, quotes or other shell characters.
valid_email() {
  case "$1" in *[!A-Za-z0-9@._+-]*|"") return 1 ;; esac
  case "$1" in ?*@?*.?*) return 0 ;; *) return 1 ;; esac
}
# ask_email asks on the terminal, so it works when the script itself is piped in.
ask_email() {
  {
    printf "\nAutoPanel gets its certificates from Let's Encrypt, which asks for a contact\n"
    printf "address for the account. It is sent only to Let's Encrypt.\n"
  } >/dev/tty
  tries=0
  while [ "$tries" -lt 3 ]; do
    printf 'Contact email: ' >/dev/tty
    IFS= read -r EMAIL </dev/tty || EMAIL=""
    if valid_email "$EMAIL"; then return 0; fi
    printf '  That is not an email address. Try again.\n' >/dev/tty
    tries=$((tries + 1))
  done
  die "no email address was given; nothing was installed"
}
if [ ! -f "$ENV_FILE" ]; then
  if [ -z "$EMAIL" ]; then
    have_tty || die "--email is required on a first install when there is no terminal to ask on (the ACME account's contact)"
    ask_email
  fi
  valid_email "$EMAIL" || die "--email $EMAIL is not an email address"
fi

# ask_ca asks which Let's Encrypt directory issues the certificates. The choice
# is not obvious, and the wrong one is costly either way: staging certificates
# are trusted by nothing, and production locks a misconfigured host out.
ask_ca() {
  {
    printf "\nWhich Let's Encrypt service should issue the certificates?\n\n"
    printf "  1) staging     Test certificates. Browsers do NOT trust them. Use it to check\n"
    printf "                 that DNS and ports 80 and 443 are right: its limits are loose,\n"
    printf "                 so a mistake costs nothing.\n"
    printf "  2) production  Real certificates, trusted by browsers. Its limits are strict:\n"
    printf "                 a name that keeps failing is refused for an hour or more.\n\n"
    printf "You can change it later in %s.\n" "$ENV_FILE"
  } >/dev/tty
  tries=0
  while [ "$tries" -lt 3 ]; do
    printf 'Choice [1]: ' >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    case "$answer" in
      ""|1|s|staging) CA=staging; return 0 ;;
      2|p|production) CA=production; return 0 ;;
    esac
    printf '  Type 1 for staging or 2 for production.\n' >/dev/tty
    tries=$((tries + 1))
  done
  die "no certificate service was chosen; nothing was installed"
}
if [ ! -f "$ENV_FILE" ] && [ -z "$CA" ]; then
  if have_tty; then
    ask_ca
  else
    CA=staging # no terminal to ask on: the safe one, and the closing lines say so
  fi
fi
if [ ! -f "$KEYFILE" ]; then
  if [ -n "$PASSFILE" ]; then
    [ -f "$PASSFILE" ] || die "no passphrase file at $PASSFILE"
    case "$(stat -c %a "$PASSFILE")" in 600|400) ;; *) die "$PASSFILE must be mode 0600" ;; esac
  else
    have_tty || die "the master passphrase needs a terminal (or --passphrase-file)"
  fi
fi

# --- the release files -------------------------------------------------------
# Found beside this script, downloaded, or built: all in a temporary directory,
# so a refused or failed fetch still leaves the host as it was.

# shellcheck disable=SC2317  # reached through the trap
cleanup() { [ -z "$TMP" ] || rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH="" ;;
  esac
}

# resolve_latest prints the latest release's tag, or fails when there is none.
# It follows the /releases/latest redirect rather than the API, which is
# rate-limited for unauthenticated callers and would need a JSON parser.
resolve_latest() {
  url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null) || return 1
  tag=${url##*/}
  case "$tag" in v[0-9]*) printf '%s\n' "$tag" ;; *) return 1 ;; esac
}

# verify_sha256 <file> <file holding "<sum>  <name>">. It fails closed: an
# empty or unreadable side is a failure, never two empty strings that match.
verify_sha256() {
  [ -s "$1" ] || die "the downloaded $1 is missing or empty"
  [ -s "$2" ] || die "the checksum file $2 is missing or empty"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify the download"
  want=$(cut -d' ' -f1 < "$2")
  got=$(sha256sum "$1" | cut -d' ' -f1)
  [ -n "$want" ] || die "no checksum could be read from $2"
  [ -n "$got" ] || die "no checksum could be computed for $1"
  [ "$want" = "$got" ] || die "checksum mismatch for $(basename "$1"): expected $want, got $got; nothing was installed"
  info "checksum verified"
}

# download <tag> fetches and unpacks the release tarball. It returns 1 when the
# release isn't there to download; a bad checksum or a bad tarball stops the install.
download() {
  asset=autopanel-$1-linux-$ARCH.tar.gz
  base=https://github.com/$REPO/releases/download/$1
  info "downloading $asset"
  curl -fsSL -o "$TMP/$asset" "$base/$asset" 2>/dev/null || return 1
  curl -fsSL -o "$TMP/$asset.sha256" "$base/$asset.sha256" 2>/dev/null || return 1
  verify_sha256 "$TMP/$asset" "$TMP/$asset.sha256"
  tar -xzf "$TMP/$asset" -C "$TMP" || die "$asset could not be unpacked"
  FILES=$TMP/autopanel-$1-linux-$ARCH
  BINARY=$FILES/autopanel
  WANT_VERSION=$1
}

go_version_ok() {
  raw=$(go env GOVERSION 2>/dev/null || true) # go1.26.9
  raw=${raw#go}
  major=${raw%%.*}
  rest=${raw#*.}
  minor=${rest%%.*}
  case "$major$minor" in *[!0-9]*|"") return 1 ;; esac
  [ "$major" -gt "$MIN_GO_MAJOR" ] && return 0
  [ "$major" -eq "$MIN_GO_MAJOR" ] && [ "$minor" -ge "$MIN_GO_MINOR" ] && return 0
  return 1
}

# build_source <ref> builds the binary from the repository at a tag or branch.
build_source() {
  need git "to build from source"
  need go "to build from source (or pass --binary with one built elsewhere)"
  go_version_ok || die "Go $MIN_GO_MAJOR.$MIN_GO_MINOR or later is required to build from source (found ${raw:-none})"
  info "cloning $REPO at $1"
  git clone --quiet --depth 1 --branch "$1" "https://github.com/$REPO.git" "$TMP/src" >/dev/null 2>&1 \
    || die "could not clone $REPO at $1"
  WANT_VERSION=$(git -C "$TMP/src" describe --tags --always) || die "could not read the source's version"
  info "building $WANT_VERSION (go $(go env GOVERSION), CGO disabled)"
  mkdir "$TMP/build"
  ( cd "$TMP/src" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/$REPO/app.Version=$WANT_VERSION" \
      -o "$TMP/build/autopanel" ./cmd/autopanel ) || die "the build failed; nothing was installed"
  cp "$TMP/src/uninstall.sh" "$TMP/src/deploy/autopanel.service" "$TMP/build/" || die "the source has no uninstall.sh or unit"
  FILES=$TMP/build
  BINARY=$FILES/autopanel
}

fetch() {
  need curl "to download a release"
  need tar "to unpack a release"
  detect_arch
  TMP=$(mktemp -d) || die "could not create a temporary directory"
  tag=$RELEASE
  if [ "$tag" = latest ]; then tag=$(resolve_latest) || tag=""; fi
  if [ "$FROM" = auto ] && [ -n "$tag" ] && [ -n "$ARCH" ] && download "$tag"; then
    return
  fi
  if [ "$FROM" = auto ]; then
    if [ -z "$tag" ]; then warn "no release to download yet; building main from source"
    else warn "no release tarball for $tag on linux/$(uname -m); building it from source"; fi
  fi
  build_source "${tag:-main}"
}

if [ -n "$BINARY" ]; then
  [ -f "$BINARY" ] || die "no binary at $BINARY"
  FILES=$HERE
elif [ "$FROM$RELEASE" = autolatest ] && [ -f "$HERE/autopanel" ] && [ -f "$HERE/autopanel.service" ] && [ -f "$HERE/uninstall.sh" ]; then
  BINARY=$HERE/autopanel
  FILES=$HERE
else
  fetch
fi
[ -f "$FILES/autopanel.service" ] || die "autopanel.service is missing from $FILES"
[ -f "$FILES/uninstall.sh" ] || die "uninstall.sh is missing from $FILES"
VERSION=$("$BINARY" --version 2>/dev/null) || die "$BINARY does not run on this host"
# The binary must be the one asked for: compare the version token exactly.
[ -z "$WANT_VERSION" ] || [ "${VERSION#autopanel }" = "$WANT_VERSION" ] \
  || die "the binary reports \"${VERSION#autopanel }\", not $WANT_VERSION; nothing was installed"
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
install -m 0644 "$FILES/autopanel.service" "$UNIT"
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
  umask 027 # --email was checked in the preflight
  {
    printf '# Written by install.sh. root:%s 0640. Holds no secrets: the Cloudflare\n' "$SVC_USER"
    printf '# token is set with certs.cloudflare.set and kept sealed in the store.\n'
    printf 'AUTOPANEL_HTTP_ADDR=%s\n' "$HTTP_ADDR"
    printf 'AUTOPANEL_HTTPS_ADDR=%s\n' "$HTTPS_ADDR"
    printf 'AUTOPANEL_ACME_CA=%s\n' "$CA"
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
  # The file and the terminal were checked in the preflight.
  if [ -n "$PASSFILE" ]; then
    head -n 1 "$PASSFILE"
    return
  fi
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
install -m 0755 "$FILES/uninstall.sh" "$UNINSTALLER"
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
case "$(sed -n 's/^AUTOPANEL_ACME_CA=//p' "$ENV_FILE" 2>/dev/null)" in
  staging)
    info "certificates come from Let's Encrypt STAGING: browsers will not trust them (test with curl -k)"
    info "when the site answers, switch to real certificates:"
    info "  sudo sed -i 's/^AUTOPANEL_ACME_CA=.*/AUTOPANEL_ACME_CA=production/' $ENV_FILE && sudo systemctl restart autopanel"
    ;;
  production) info "certificates come from Let's Encrypt production: real, trusted certificates" ;;
  *) info "certificates come from the directory AUTOPANEL_ACME_CA names in $ENV_FILE" ;;
esac
info "behind Cloudflare's proxy: sudo -u $SVC_USER autopanel --call certs.cloudflare.set '{\"token\":\"…\"}'"
info "remove: sudo autopanel-uninstall --check"
