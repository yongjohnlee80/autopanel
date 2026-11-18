// Package stalwart is AutoPanel's SDK for Stalwart: provider.Product and
// provider.Server for Stalwart v1, managed through its JMAP management API.
// It alone knows Stalwart's image, ports, first start, objects and quirks;
// core/mail knows none of them.
//
// Pinned: Stalwart v1.1.0. What it does that the code relies on was tested
// against that version on a throwaway machine (docs/decisions/mail.md).
//
// Decision: docs/decisions/mail.md#mails-rules-name-no-mail-server
package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// Image is the Stalwart AutoPanel runs, pinned by digest. A new Stalwart is a
// new AutoPanel release, applied through the usual review. v1.x keeps its
// schema, so a v1 upgrade needs no migration.
const Image = "docker.io/stalwartlabs/stalwart@sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e" // v1.1.0

// inside are Stalwart's own ports in its container, by mail's port names:
// high ports, so it binds nothing below 1024.
var inside = map[string]int{"smtp": 2525, "submissions": 4465, "submission": 5587, "imaps": 9993}

// manageInside is Stalwart's management API in its container.
const manageInside = 8080

// Product is Stalwart as AutoPanel runs it.
type Product struct{}

var _ provider.Product = Product{}

func (Product) Name() string { return "Stalwart" }

// Service is the compose service Compose writes.
func (Product) Service() string { return "stalwart" }

// Compose is the definition AutoPanel writes: Stalwart pinned, as user 2000
// (keep-id: its files are the stack user's on the host), with a read-only
// root, its three writable folders as data, every port on loopback only, and
// one capability, which the binary carries as a file capability and without
// which the kernel refuses to run it (Stalwart binds no port below 1024).
func (Product) Compose(st provider.Stack) []byte {
	ports, manage := st.Ports, st.Manage
	var b strings.Builder
	b.WriteString(`# Mail: Stalwart, written by AutoPanel. It is changed from Mail, not by hand.
services:
  stalwart:
    image: ` + Image + `
    user: "2000:2000"
    volumes:
      - ./etc:/etc/stalwart
      - ./data:/var/lib/stalwart
      - ./log:/var/log/stalwart
    ports:
`)
	for _, p := range ports {
		b.WriteString(`      - "127.0.0.1:` + strconv.Itoa(p.Loopback) + ":" + strconv.Itoa(inside[p.Name]) + `"
`)
	}
	b.WriteString(`      - "127.0.0.1:` + strconv.Itoa(manage) + ":" + strconv.Itoa(manageInside) + `"
    mem_limit: 250m
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
`)
	return []byte(b.String())
}

// x86v2 are the flags of x86-64-v2 as /proc/cpuinfo names them (pni is SSE3).
var x86v2 = []string{"pni", "ssse3", "sse4_1", "sse4_2", "popcnt", "cx16", "lahf_lm"}

// CPU: Stalwart's x86 build needs x86-64-v2, and exits at once on less.
func (Product) CPU(arch string, flags map[string]bool) error {
	if arch != "amd64" {
		return nil
	}
	var missing []string
	for _, f := range x86v2 {
		if !flags[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Stalwart needs x86-64-v2, and the processor lacks %s (on a virtual machine, set its CPU type to host or x86-64-v2)", strings.Join(missing, ", "))
	}
	return nil
}

// bannerPassword is the line of Stalwart's first-start banner that holds the
// one-time password: "   password: <it>".
var bannerPassword = regexp.MustCompile(`^\s*password:\s*(\S+)\s*$`)

func (Product) FirstCredential(line string) (string, bool) {
	if m := bannerPassword.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// passwordLine is the banner line, wherever it sits in a log line.
var passwordLine = regexp.MustCompile(`(?i)(password:\s*)\S+`)

// Mask hides the one-time password in Stalwart's log lines.
func (Product) Mask(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = passwordLine.ReplaceAllString(l, "${1}[hidden]")
	}
	return out
}

func (Product) Client(base string, apiKey func(context.Context) (string, error)) provider.Server {
	return server{c: NewClient(base, Bearer(apiKey))}
}

// sealedAdmin is the permanent administrator x:Bootstrap answers: kept for a
// lost API key, never used otherwise.
const sealedAdmin = "admin"

// Bootstrap: the one-time password Stalwart printed sets it up, which answers
// with the permanent administrator (sealed at once); a restart ends the
// one-time password; the administrator moves the listeners to the ports and
// the trust the gate needs and makes AutoPanel's API key (sealed); a restart
// applies the listeners.
func (Product) Bootstrap(ctx context.Context, env provider.Env) error {
	set := env.Settings()
	var admin Admin
	if raw, err := env.Sealed(ctx, sealedAdmin); err == nil {
		_ = json.Unmarshal(raw, &admin) // set up already, by an earlier try
	} else if !errors.Is(err, provider.ErrNoSecret) {
		return err
	}
	if admin.Secret == "" {
		once, err := env.FirstCredential(ctx)
		if err != nil {
			return fmt.Errorf("the one-time password: %w", err)
		}
		c := NewClient(env.Base(), Basic("admin", once))
		admin, err = c.SetUp(ctx, Bootstrap{Hostname: set.Host, Domain: set.FirstDomain})
		if err != nil {
			return fmt.Errorf("setting Stalwart up: %w", err)
		}
		raw, _ := json.Marshal(admin)
		if err := env.Seal(ctx, sealedAdmin, raw); err != nil {
			return fmt.Errorf("sealing the administrator: %w", err)
		}
		if err := env.Restart(ctx); err != nil {
			return err
		}
	}
	c := NewClient(env.Base(), Basic(admin.Username, admin.Secret))
	if _, err := c.Domains(ctx); err != nil {
		return fmt.Errorf("signing in as the administrator: %w", err)
	}
	forwarder, err := env.Forwarder(ctx)
	if err != nil {
		return fmt.Errorf("the forwarder's address: %w", err)
	}
	if err := c.ConfigureListeners(ctx, Listeners, forwarder); err != nil {
		return fmt.Errorf("the listeners: %w", err)
	}
	if _, err := env.Sealed(ctx, provider.SealedAPIKey); errors.Is(err, provider.ErrNoSecret) {
		_, key, err := c.CreateAPIKey(ctx, "autopanel core")
		if err != nil {
			return fmt.Errorf("the API key: %w", err)
		}
		if err := env.Seal(ctx, provider.SealedAPIKey, []byte(key)); err != nil {
			return fmt.Errorf("sealing the API key: %w", err)
		}
	} else if err != nil {
		return err
	}
	return env.Restart(ctx) // the listeners apply at a start
}
