package app

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/dao"
)

// Config is AutoPanel's configuration, read from the environment. The
// PostgreSQL DSN comes only from the environment; the Cloudflare token is not
// configuration at all: it is set through certs.cloudflare.set and kept sealed
// in the store (R8).
//
// The shipped defaults bind loopback; a deployment widens the gate to :80 and
// :443 (security-core-hardening, "loopback by default").
type Config struct {
	StateDir   string // the SQLite store; systemd's StateDirectory
	Socket     string // the control socket, for the panel and the CLI; in the core's own runtime directory
	LinkSocket string // the link socket, for the gate process; in a directory the gate's group can enter
	GateUser   string // the user the gate process runs as, the only peer the link socket admits; "" for this process's own user
	Engine     string // "sqlite" (default) or "postgres"
	DSN        string // PostgreSQL, from AUTOPANEL_POSTGRES_DSN
	HTTPAddr   string // the gate's plain listener: ACME HTTP-01 and the redirect to HTTPS
	HTTPSAddr  string // the gate's TLS listener
	CA         string // the ACME directory URL
	Email      string // the ACME account contact
	Keyfile    string // the service keyslot's keyfile, outside the state directory
	Services   string // the directory that holds each deployed service's own directory
	Stacks     string // the directory that holds each stack's definition folder
	Trusted    []netip.Prefix
}

// The core unit's directories (deploy/autopanel-core.service), and the keyfile
// install.sh makes, in a directory of its own outside the state directory.
const (
	systemState   = "/var/lib/autopanel"
	systemRuntime = "/run/autopanel-core" // the control socket: root's alone
	systemLink    = "/run/autopanel-link" // the link socket: root's, and the gate's group may enter
	systemKeyfile = "/etc/autopanel/keyslot/service.key"
	// Each deployed service's directory, the home of that service's user. It
	// is beside the core's state, not inside it: the state is root's alone.
	systemServices = "/var/lib/autopanel-services"
	// Each stack's definition, written by the administrator: root's alone.
	systemStacks = "/etc/autopanel/stacks"
)

// linkSocket is where the link socket is: what AUTOPANEL_LINK_SOCKET says,
// the core unit's directory when it exists, and otherwise beside the control
// socket in runtime (a development run, where one user runs both processes).
func linkSocket(runtime string) string {
	if isDir(systemLink) {
		runtime = systemLink
	}
	return env("AUTOPANEL_LINK_SOCKET", filepath.Join(runtime, "link.sock"))
}

// userRuntime is this user's own runtime directory for AutoPanel, for a run
// outside the units.
func userRuntime(state string) string {
	runtime := env("XDG_RUNTIME_DIR", state)
	if runtime != state {
		runtime = filepath.Join(runtime, "autopanel")
	}
	return runtime
}

// GateLinkSocket is the link socket as the gate process finds it. The gate
// reads no other configuration: the rest comes over the link.
func GateLinkSocket() string {
	home, _ := os.UserHomeDir()
	return linkSocket(userRuntime(filepath.Join(home, ".local", "state", "autopanel")))
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// LoadConfig reads the environment.
func LoadConfig() (Config, error) {
	state := env("AUTOPANEL_STATE_DIR", os.Getenv("STATE_DIRECTORY"))
	if state == "" && isDir(systemState) {
		state = systemState // the unit's StateDirectory, for a CLI run outside the unit
	}
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, err
		}
		state = filepath.Join(home, ".local", "state", "autopanel")
	}
	// The core's unit names two runtime directories, so systemd gives them as
	// a colon-separated list: the control socket's is the first.
	runtime, _, _ := strings.Cut(os.Getenv("RUNTIME_DIRECTORY"), ":")
	if runtime == "" && isDir(systemRuntime) {
		runtime = systemRuntime // so `sudo autopanel --ui` finds the unit's socket
	}
	if runtime == "" {
		runtime = userRuntime(state)
	}
	c := Config{
		StateDir:   state,
		Socket:     env("AUTOPANEL_SOCKET", filepath.Join(runtime, "control.sock")),
		LinkSocket: linkSocket(runtime),
		GateUser:   os.Getenv("AUTOPANEL_GATE_USER"),
		Engine:     env("AUTOPANEL_STORE_ENGINE", dao.DialectSQLite),
		DSN:        os.Getenv("AUTOPANEL_POSTGRES_DSN"),
		HTTPAddr:   env("AUTOPANEL_HTTP_ADDR", "127.0.0.1:8080"),
		HTTPSAddr:  env("AUTOPANEL_HTTPS_ADDR", "127.0.0.1:8443"),
		Email:      os.Getenv("AUTOPANEL_ACME_EMAIL"),
		Keyfile:    os.Getenv("AUTOPANEL_KEYFILE"),
		Services:   env("AUTOPANEL_SERVICES_DIR", systemServices),
		Stacks:     env("AUTOPANEL_STACKS_DIR", systemStacks),
	}
	if c.GateUser == "" && os.Getuid() == 0 {
		c.GateUser = "autopanel" // the units: a root core, and the gate as the user install.sh made
	}
	if c.Keyfile == "" {
		if isDir(filepath.Dir(systemKeyfile)) {
			c.Keyfile = systemKeyfile
		} else {
			c.Keyfile = filepath.Join(filepath.Dir(state), "autopanel-keyslot", "service.key") // beside, never inside, the state directory
		}
	}
	switch ca := env("AUTOPANEL_ACME_CA", "staging"); ca {
	case "staging":
		c.CA = certmagic.LetsEncryptStagingCA
	case "production":
		c.CA = certmagic.LetsEncryptProductionCA
	default:
		if !strings.HasPrefix(ca, "https://") {
			return Config{}, fmt.Errorf("AUTOPANEL_ACME_CA: %q is not staging, production or an https URL", ca)
		}
		c.CA = ca
	}
	for _, s := range strings.FieldsFunc(os.Getenv("AUTOPANEL_TRUSTED_PROXIES"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Config{}, fmt.Errorf("AUTOPANEL_TRUSTED_PROXIES: %q: %w", s, err)
		}
		c.Trusted = append(c.Trusted, p.Masked())
	}
	if c.Engine == dao.DialectPostgres && c.DSN == "" {
		return Config{}, errors.New("AUTOPANEL_STORE_ENGINE=postgres needs AUTOPANEL_POSTGRES_DSN")
	}
	return c, nil
}
