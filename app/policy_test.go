package app

import (
	"sort"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// TestEveryVerbHasADecision: each verb of the control socket is in this table
// with its area, whether it mutates, and whether its answer is Plain, so no
// verb lands without a decision on each (H3). A verb added later fails here
// until it is placed; one left unmarked is Sensitive, kept from the read-only
// roles.
func TestEveryVerbHasADecision(t *testing.T) {
	type d struct {
		area    string
		mutates bool
		plain   bool
	}
	want := map[string]d{
		"auth.login": {"auth", false, true}, "auth.token.login": {"auth", false, true}, "auth.status": {"auth", false, true},
		"auth.whoami": {"auth", false, true}, "auth.user.list": {"auth", false, false},
		"auth.user.add": {"auth", true, false}, "auth.user.role": {"auth", true, false}, "auth.user.reset": {"auth", true, false},
		"auth.user.disable": {"auth", true, false}, "auth.user.unlock": {"auth", true, false}, "auth.user.remove": {"auth", true, false},
		"auth.passphrase.change": {"auth", true, false}, "auth.totp.begin": {"auth", true, false}, "auth.totp.confirm": {"auth", true, false},
		"auth.totp.disable": {"auth", true, false}, "auth.token.list": {"auth", false, true}, "auth.token.create": {"auth", true, false},
		"auth.token.revoke": {"auth", true, false},

		"gate.route.list": {"gate", false, true}, "gate.route.add": {"gate", true, false}, "gate.route.update": {"gate", true, false},
		"gate.route.remove": {"gate", true, false}, "gate.domain.list": {"gate", false, true}, "gate.domain.add": {"gate", true, false},
		"gate.domain.remove": {"gate", true, false},
		"gate.forward.list":  {"gate", false, true}, "gate.forward.check": {"gate", false, true},
		"gate.forward.add": {"gate", true, false}, "gate.forward.update": {"gate", true, false}, "gate.forward.remove": {"gate", true, false},
		"gate.tunnel.agent.list": {"gate", false, true}, "gate.tunnel.agent.add": {"gate", true, false}, "gate.tunnel.agent.remove": {"gate", true, false},

		"certs.ca.set": {"certs", true, false}, "certs.cloudflare.set": {"certs", true, false}, "certs.cloudflare.clear": {"certs", true, false},
		"certs.list": {"certs", false, true},

		"sys.status": {"sys", false, true}, "sys.metrics": {"sys", false, true}, "sys.ports": {"sys", false, true}, "sys.checks": {"sys", false, true},
		"sys.prefs.get": {"sys", false, true}, "sys.prefs.set": {"sys", true, false},
		"sys.audit.list": {"sys", false, false}, "sys.logins": {"sys", false, false},
		"sys.api.get": {"sys.admin", false, true}, "sys.api.set": {"sys.admin", true, false},
		"sys.gate.restart": {"sys.admin", true, false}, "sys.gate.stop": {"sys.admin", true, false},
		"sys.firewall.get": {"sys.admin", false, true}, "sys.firewall.plan": {"sys.admin", false, true},
		"sys.firewall.allow": {"sys.admin", true, false}, "sys.firewall.revoke": {"sys.admin", true, false},
		"sys.firewall.enable": {"sys.admin", true, false}, "sys.firewall.confirm": {"sys.admin", true, false},
		"sys.firewall.disable": {"sys.admin", true, false},

		"services.available": {"services", false, true}, "services.check": {"services", false, true}, "services.list": {"services", false, true},
		"services.browse": {"services", false, false}, "services.preview": {"services", false, false}, "services.logs": {"services", false, false},
		"services.import": {"services", true, false}, "services.reimport": {"services", true, false}, "services.prepare": {"services", true, false},
		"services.add": {"services", true, false}, "services.apply": {"services", true, false}, "services.pull": {"services", true, false},
		"services.start": {"services", true, false}, "services.stop": {"services", true, false}, "services.restart": {"services", true, false},
		"services.remove": {"services", true, false},

		"mail.status": {"mail", false, true}, "mail.records": {"mail", false, true}, "mail.domain.list": {"mail", false, true},
		"mail.account.list": {"mail", false, true}, "mail.setup": {"mail.admin", true, false}, "mail.setup.apply": {"mail.admin", true, false}, "mail.ports.open": {"mail.admin", true, false}, "mail.remove": {"mail.admin", true, false},
		"mail.domain.add": {"mail", true, false}, "mail.domain.remove": {"mail", true, false}, "mail.records.takeover": {"mail", true, false},
		"mail.sync": {"mail", true, false}, "mail.account.add": {"mail", true, false}, "mail.account.lock": {"mail", true, false},
		"mail.apppassword.list": {"mail", false, true}, "mail.apppassword.add": {"mail", true, false},
		"mail.apppassword.keep": {"mail", true, false}, "mail.apppassword.revoke": {"mail", true, false},
		"mail.account.quota": {"mail", true, false}, "mail.account.remove": {"mail", true, false},

		"site.add": {"site.admin", true, false}, "site.list": {"site.admin", false, true}, "site.remove": {"site.admin", true, false},
		"site.doc.put": {"site", true, false}, "site.doc.list": {"site", false, true}, "site.doc.get": {"site", false, false},
		"site.doc.remove": {"site", true, false},
		"site.asset.put":  {"site", true, false}, "site.asset.list": {"site", false, false}, "site.asset.remove": {"site", true, false},
	}
	seen := map[string]bool{}
	var unplaced []string
	for _, m := range contractModules() {
		if m.Name() == "link" { // the gate's socket: Open verbs, no roles
			continue
		}
		for _, v := range m.Verbs() {
			seen[v.Verb] = true
			w, ok := want[v.Verb]
			if !ok {
				unplaced = append(unplaced, v.Verb)
				continue
			}
			got := d{v.AreaOf(), v.Mutates, v.Discloses == module.Plain}
			if got != w {
				t.Errorf("%s: (area, mutates, plain) = %v, want %v", v.Verb, got, w)
			}
		}
	}
	sort.Strings(unplaced)
	if len(unplaced) > 0 {
		t.Errorf("verbs with no decision in this table: %s", strings.Join(unplaced, ", "))
	}
	for v := range want {
		if !seen[v] {
			t.Errorf("%s is in the table and no module has it", v)
		}
	}
}

// TestWhatEachRoleReaches: the roles over the real contracts (result 1).
func TestWhatEachRoleReaches(t *testing.T) {
	c := map[string]module.Contract{}
	for _, m := range contractModules() {
		for _, v := range m.Verbs() {
			c[v.Verb] = v.Contract
		}
	}
	for _, x := range []struct {
		role auth.Role
		verb string
		want bool
	}{
		{auth.RoleViewer, "services.list", true}, {auth.RoleViewer, "services.logs", false}, {auth.RoleViewer, "services.browse", false},
		{auth.RoleViewer, "sys.logins", false}, {auth.RoleViewer, "sys.audit.list", false}, {auth.RoleViewer, "gate.route.add", false},
		{auth.RoleMail, "mail.account.add", true}, {auth.RoleMail, "mail.setup", false}, {auth.RoleMail, "services.list", false},
		{auth.RoleMail, "gate.route.list", true}, {auth.RoleOperator, "services.logs", true}, {auth.RoleOperator, "certs.cloudflare.set", false},
		{auth.RoleOperator, "sys.gate.stop", false}, {auth.RoleOperator, "auth.user.add", false}, {auth.RoleOperator, "mail.setup", true},
		{auth.RoleAdmin, "auth.user.add", true}, {auth.RoleAdmin, "sys.gate.stop", true},
		{auth.RoleViewer, "auth.passphrase.change", true}, {auth.RoleViewer, "auth.user.list", false},
	} {
		if got := auth.Allows(x.role, c[x.verb]); got != x.want {
			t.Errorf("%s calling %s: %v, want %v", x.role, x.verb, got, x.want)
		}
	}
}
