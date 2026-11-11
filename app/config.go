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

// Config is AutoPanel's configuration, read from the environment. Secrets (the
// PostgreSQL DSN, the Cloudflare token) come only from the environment or the
// unit's credential files, never from a file in the repository (R8).
//
// The shipped defaults bind loopback; a deployment widens the gate to :80 and
// :443 (security-core-hardening, "loopback by default").
type Config struct {
	StateDir  string // the SQLite store; systemd's StateDirectory
	Socket    string // the control socket; under systemd's RuntimeDirectory
	Engine    string // "sqlite" (default) or "postgres"
	DSN       string // PostgreSQL, from AUTOPANEL_POSTGRES_DSN
	HTTPAddr  string // the gate's plain listener: ACME HTTP-01 and the redirect to HTTPS
	HTTPSAddr string // the gate's TLS listener
	CA        string // the ACME directory URL
	Email     string // the ACME account contact
	CFToken   string // a Cloudflare API token: set, every certificate uses DNS-01
	Trusted   []netip.Prefix
}

// The systemd unit's directories (deploy/autopanel.service).
const (
	systemState   = "/var/lib/autopanel"
	systemRuntime = "/run/autopanel"
)

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
	runtime := os.Getenv("RUNTIME_DIRECTORY")
	if runtime == "" && isDir(systemRuntime) {
		runtime = systemRuntime // so `sudo -u autopanel autopanel --ui` finds the unit's socket
	}
	if runtime == "" {
		runtime = env("XDG_RUNTIME_DIR", state)
		if runtime != state {
			runtime = filepath.Join(runtime, "autopanel")
		}
	}
	c := Config{
		StateDir:  state,
		Socket:    env("AUTOPANEL_SOCKET", filepath.Join(runtime, "control.sock")),
		Engine:    env("AUTOPANEL_STORE_ENGINE", dao.DialectSQLite),
		DSN:       os.Getenv("AUTOPANEL_POSTGRES_DSN"),
		HTTPAddr:  env("AUTOPANEL_HTTP_ADDR", "127.0.0.1:8080"),
		HTTPSAddr: env("AUTOPANEL_HTTPS_ADDR", "127.0.0.1:8443"),
		Email:     os.Getenv("AUTOPANEL_ACME_EMAIL"),
		CFToken:   os.Getenv("AUTOPANEL_CLOUDFLARE_API_TOKEN"),
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

// Challenge names how certificates are validated, for status.
func (c Config) Challenge() string {
	if c.CFToken != "" {
		return "dns-01 (cloudflare)"
	}
	return "http-01, tls-alpn-01"
}
