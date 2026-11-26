package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/yongjohnlee80/autopanel/core/forward"
	coretunnel "github.com/yongjohnlee80/autopanel/core/tunnel"
	"io"
	"slices"

	"github.com/yongjohnlee80/golib/server/rpc"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
	"github.com/yongjohnlee80/autopanel/internal/ui"
)

// uiClient is the TUI's Client over the control socket: every call is a verb.
// The panel's login dialog logs the connection in (Login); until then the
// service refuses every other verb.
type uiClient struct{ c *hostcontrol.Client }

// publicErrors are the errors the panel tells apart by their wire codes: the
// stacks', the routes', mail's, the users' and the API's.
var publicErrors = slices.Concat((&services.Module{}).Errors(), (&gate.Module{}).Errors(), (&mail.Module{}).Errors(), (&auth.Module{}).Errors(), (&apiModule{}).Errors(), (&forward.Module{}).Errors(), (&coretunnel.Module{}).Errors())

// known is err with the error its wire code names wrapped in, so the panel
// can tell it apart (errors.Is); the daemon's message is kept beside it.
func known(err error) error {
	var re *rpc.Error
	if !errors.As(err, &re) {
		return err
	}
	for _, e := range publicErrors {
		if e.Code == re.Code {
			return fmt.Errorf("%w (%s)", e.Err, re.Message)
		}
	}
	return err
}

// call is one verb, its error made known.
func (u uiClient) call(ctx context.Context, verb string, param, result any) error {
	return known(u.c.Call(ctx, verb, param, result))
}

func (u uiClient) Login(ctx context.Context, user, passphrase, code string) (auth.LoggedIn, error) {
	var in auth.LoggedIn
	return in, u.call(ctx, "auth.login", auth.Login{User: user, Passphrase: passphrase, Code: code}, &in)
}

func (u uiClient) VaultLocked(ctx context.Context) (bool, error) {
	var s auth.Status
	err := u.call(ctx, "auth.status", nil, &s)
	return s.VaultLocked, err
}

func (u uiClient) Whoami(ctx context.Context) (auth.Whoami, error) {
	var w auth.Whoami
	return w, u.call(ctx, "auth.whoami", nil, &w)
}

func (u uiClient) Users(ctx context.Context) ([]auth.UserView, error) {
	var us []auth.UserView
	return us, u.call(ctx, "auth.user.list", nil, &us)
}

func (u uiClient) UserAdd(ctx context.Context, name, role, pass string) error {
	return u.call(ctx, "auth.user.add", auth.UserAsk{Name: name, Role: auth.Role(role), Passphrase: pass}, nil)
}

func (u uiClient) UserRole(ctx context.Context, name, role, pass string) error {
	return u.call(ctx, "auth.user.role", auth.UserAsk{Name: name, Role: auth.Role(role), Passphrase: pass}, nil)
}

func (u uiClient) UserReset(ctx context.Context, name, pass string) error {
	return u.call(ctx, "auth.user.reset", auth.UserAsk{Name: name, Passphrase: pass}, nil)
}

func (u uiClient) UserDisable(ctx context.Context, name string, disabled bool) error {
	return u.call(ctx, "auth.user.disable", auth.UserAsk{Name: name, Disabled: disabled}, nil)
}

func (u uiClient) UserUnlock(ctx context.Context, name string) error {
	return u.call(ctx, "auth.user.unlock", auth.UserAsk{Name: name}, nil)
}

func (u uiClient) UserRemove(ctx context.Context, name string) error {
	return u.call(ctx, "auth.user.remove", auth.UserAsk{Name: name}, nil)
}

func (u uiClient) PassphraseChange(ctx context.Context, old, new string) error {
	return u.call(ctx, "auth.passphrase.change", auth.PassphraseAsk{Old: old, New: new}, nil)
}

func (u uiClient) TOTPBegin(ctx context.Context, passphrase string) (auth.Enrol, error) {
	var e auth.Enrol
	return e, u.call(ctx, "auth.totp.begin", auth.PassAsk{Passphrase: passphrase}, &e)
}

func (u uiClient) TOTPConfirm(ctx context.Context, code string) (auth.Recovery, error) {
	var r auth.Recovery
	return r, u.call(ctx, "auth.totp.confirm", auth.CodeAsk{Code: code}, &r)
}

func (u uiClient) TOTPDisable(ctx context.Context, passphrase, code string) error {
	return u.call(ctx, "auth.totp.disable", auth.CodeAsk{Code: code, Passphrase: passphrase}, nil)
}

func (u uiClient) Tokens(ctx context.Context) ([]auth.TokenView, error) {
	var ts []auth.TokenView
	return ts, u.call(ctx, "auth.token.list", nil, &ts)
}

func (u uiClient) TokenCreate(ctx context.Context, name, role string, days int, passphrase string) (auth.NewToken, error) {
	var t auth.NewToken
	return t, u.call(ctx, "auth.token.create", auth.TokenAsk{Name: name, Role: auth.Role(role), Days: days, Passphrase: passphrase}, &t)
}

func (u uiClient) TokenRevoke(ctx context.Context, id int64) error {
	return u.call(ctx, "auth.token.revoke", auth.TokenAsk{ID: id}, nil)
}

func (u uiClient) Routes(ctx context.Context) ([]gate.RouteView, error) {
	var rs []gate.RouteView
	return rs, u.call(ctx, "gate.route.list", nil, &rs)
}

func (u uiClient) Status(ctx context.Context) (ui.Status, error) {
	var s ui.Status
	return s, u.call(ctx, "sys.status", nil, &s)
}

func (u uiClient) Add(ctx context.Context, s gate.RouteSpec) error {
	return u.call(ctx, "gate.route.add", s, nil)
}

func (u uiClient) Update(ctx context.Context, s gate.RouteSpec) error {
	return u.call(ctx, "gate.route.update", s, nil)
}

func (u uiClient) Remove(ctx context.Context, id int64) error {
	return u.call(ctx, "gate.route.remove", gate.RouteRef{ID: id}, nil)
}

func (u uiClient) SetCA(ctx context.Context, ca string) error {
	return u.call(ctx, "certs.ca.set", CA{CA: ca}, nil)
}

func (u uiClient) SetCloudflare(ctx context.Context, token string) error {
	return u.call(ctx, "certs.cloudflare.set", Token{Token: token}, nil)
}

func (u uiClient) ClearCloudflare(ctx context.Context) error {
	return u.call(ctx, "certs.cloudflare.clear", nil, nil)
}

func (u uiClient) Domains(ctx context.Context) ([]gate.DomainView, error) {
	var ds []gate.DomainView
	return ds, u.call(ctx, "gate.domain.list", nil, &ds)
}

func (u uiClient) APISettings(ctx context.Context) (ui.API, error) {
	var s APISettings
	err := u.call(ctx, "sys.api.get", nil, &s)
	return ui.API{Host: s.Host, Allow: s.Allow}, err
}

func (u uiClient) SetAPI(ctx context.Context, a ui.API) (ui.API, error) {
	var s APISettings
	err := u.call(ctx, "sys.api.set", APISettings{Host: a.Host, Allow: a.Allow}, &s)
	return ui.API{Host: s.Host, Allow: s.Allow}, err
}

func (u uiClient) Agents(ctx context.Context) ([]coretunnel.View, error) {
	var as []coretunnel.View
	return as, u.call(ctx, "gate.tunnel.agent.list", nil, &as)
}

func (u uiClient) AddAgent(ctx context.Context, name string) (coretunnel.Added, error) {
	var a coretunnel.Added
	return a, u.call(ctx, "gate.tunnel.agent.add", coretunnel.Name{Name: name}, &a)
}

func (u uiClient) RemoveAgent(ctx context.Context, id int64) error {
	return u.call(ctx, "gate.tunnel.agent.remove", coretunnel.Ref{ID: id}, nil)
}

func (u uiClient) Forwards(ctx context.Context) ([]forward.View, error) {
	var fs []forward.View
	return fs, u.call(ctx, "gate.forward.list", nil, &fs)
}

func (u uiClient) CheckForward(ctx context.Context, s forward.Spec) (forward.Review, error) {
	var r forward.Review
	return r, u.call(ctx, "gate.forward.check", s, &r)
}

func (u uiClient) AddForward(ctx context.Context, a forward.Apply) (forward.View, error) {
	var v forward.View
	return v, u.call(ctx, "gate.forward.add", a, &v)
}

func (u uiClient) RemoveForward(ctx context.Context, id int64) error {
	return u.call(ctx, "gate.forward.remove", forward.Ref{ID: id}, nil)
}

func (u uiClient) AddDomain(ctx context.Context, name string) error {
	return u.call(ctx, "gate.domain.add", gate.DomainRef{Name: name}, nil)
}

func (u uiClient) RemoveDomain(ctx context.Context, name string) error {
	return u.call(ctx, "gate.domain.remove", gate.DomainRef{Name: name}, nil)
}

func (u uiClient) Metrics(ctx context.Context) (ui.Metrics, error) {
	var m ui.Metrics
	return m, u.call(ctx, "sys.metrics", nil, &m)
}

func (u uiClient) Certificates(ctx context.Context) ([]ui.Cert, error) {
	var cs []ui.Cert
	return cs, u.call(ctx, "certs.list", nil, &cs)
}

func (u uiClient) AuditLog(ctx context.Context) ([]ui.AuditEntry, error) {
	var es []ui.AuditEntry
	return es, u.call(ctx, "sys.audit.list", nil, &es)
}

func (u uiClient) Logins(ctx context.Context) (ui.Logins, error) {
	var l ui.Logins
	return l, u.call(ctx, "sys.logins", nil, &l)
}

func (u uiClient) Ports(ctx context.Context) ([]ui.Port, error) {
	var ps []ui.Port
	return ps, u.call(ctx, "sys.ports", nil, &ps)
}

func (u uiClient) Checks(ctx context.Context) ([]ui.Check, error) {
	var cs []ui.Check
	return cs, u.call(ctx, "sys.checks", nil, &cs)
}

func (u uiClient) Firewall(ctx context.Context) (sysinfo.Firewall, error) {
	var fw sysinfo.Firewall
	return fw, u.call(ctx, "sys.firewall.get", nil, &fw)
}

func (u uiClient) FirewallPlan(ctx context.Context) (corefw.EnablePlan, error) {
	var p corefw.EnablePlan
	return p, u.call(ctx, "sys.firewall.plan", nil, &p)
}

func (u uiClient) FirewallAllow(ctx context.Context, a corefw.AllowAsk) error {
	return u.call(ctx, "sys.firewall.allow", a, nil)
}

func (u uiClient) FirewallRevoke(ctx context.Context, id string) error {
	return u.call(ctx, "sys.firewall.revoke", RevokeAsk{ID: id}, nil)
}

func (u uiClient) FirewallEnable(ctx context.Context, plan string, allow []string) (corefw.Armed, error) {
	var a corefw.Armed
	if allow == nil {
		allow = []string{}
	}
	return a, u.call(ctx, "sys.firewall.enable", corefw.EnableAsk{Plan: plan, Allow: allow}, &a)
}

func (u uiClient) FirewallConfirm(ctx context.Context) error {
	return u.call(ctx, "sys.firewall.confirm", nil, nil)
}

func (u uiClient) FirewallDisable(ctx context.Context) error {
	return u.call(ctx, "sys.firewall.disable", nil, nil)
}

func (u uiClient) Stacks(ctx context.Context) ([]services.View, error) {
	var vs []services.View
	return vs, u.call(ctx, "services.list", nil, &vs)
}

func (u uiClient) Browse(ctx context.Context, path string) (services.Listing, error) {
	var l services.Listing
	return l, u.call(ctx, "services.browse", services.Browse{Path: path}, &l)
}

func (u uiClient) Preview(ctx context.Context, path string) (services.PreviewText, error) {
	var p services.PreviewText
	return p, u.call(ctx, "services.preview", services.Browse{Path: path}, &p)
}

func (u uiClient) ImportStack(ctx context.Context, from, name string) (services.Imported, error) {
	var got services.Imported
	return got, u.call(ctx, "services.import", services.Import{From: from, Name: name}, &got)
}

func (u uiClient) ReimportStack(ctx context.Context, name string) (services.Imported, error) {
	var got services.Imported
	return got, u.call(ctx, "services.reimport", services.Ref{Name: name}, &got)
}

func (u uiClient) CheckStack(ctx context.Context, name string) (services.Review, error) {
	var r services.Review
	return r, u.call(ctx, "services.check", services.Ref{Name: name}, &r)
}

func (u uiClient) ApplyStack(ctx context.Context, verb, name, accept string, open []corefw.Want) error {
	switch verb {
	case "prepare", "add", "apply":
	default:
		return fmt.Errorf("no apply verb %q", verb)
	}
	// services.changed is told apart: the panel reviews the definition again.
	return u.call(ctx, "services."+verb, services.Accept{Name: name, Accept: accept, Open: open}, nil)
}

func (u uiClient) PullStack(ctx context.Context, name, service string) error {
	return u.call(ctx, "services.pull", services.Ref{Name: name, Service: service}, nil)
}

func (u uiClient) StackUnit(ctx context.Context, action, name, service string) error {
	switch action {
	case "start", "stop", "restart":
		return u.call(ctx, "services."+action, services.Ref{Name: name, Service: service}, nil)
	}
	return fmt.Errorf("no unit action %q", action)
}

func (u uiClient) RemoveStack(ctx context.Context, name string, purge bool) error {
	return u.call(ctx, "services.remove", services.Remove{Name: name, Purge: purge}, nil)
}

func (u uiClient) StackLogs(ctx context.Context, name, service string) ([]string, error) {
	var l services.Logs
	return l.Lines, u.call(ctx, "services.logs", services.LogsAsk{Name: name, Service: service}, &l)
}

func (u uiClient) Prefs(ctx context.Context) (ui.Prefs, error) {
	var p ui.Prefs
	return p, u.call(ctx, "sys.prefs.get", nil, &p)
}

func (u uiClient) SetPrefs(ctx context.Context, p ui.Prefs) error {
	return u.call(ctx, "sys.prefs.set", Prefs{Theme: p.Theme, Language: p.Language}, nil)
}

func init() {
	runUI = func(stderr io.Writer) int {
		ctx := context.Background()
		c, err := dial(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "connecting to AutoPanel: %v\n", err)
			return 1
		}
		defer c.Close()
		if err := ui.Run(ctx, uiClient{c}, Version); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
}

// --- Mail ---------------------------------------------------------------------

func (u uiClient) MailStatus(ctx context.Context) (mail.Status, error) {
	var s mail.Status
	return s, u.call(ctx, "mail.status", nil, &s)
}

func (u uiClient) MailQueue(ctx context.Context) (mail.QueueView, bool, error) {
	var q mail.QueueView
	err := u.call(ctx, "mail.queue", nil, &q)
	if errors.Is(err, auth.ErrForbidden) {
		return mail.QueueView{}, false, nil
	}
	return q, err == nil, err
}

func (u uiClient) MailSetup(ctx context.Context, host, domain string) (mail.Setup, error) {
	var s mail.Setup
	return s, u.call(ctx, "mail.setup", mail.SetupAsk{Host: host, Domain: domain}, &s)
}

func (u uiClient) MailPortsOpen(ctx context.Context, ports []int) error {
	return u.call(ctx, "mail.ports.open", mail.PortsAsk{Ports: ports}, nil)
}

func (u uiClient) MailRepairCheck(ctx context.Context) (mail.Diagnosis, error) {
	var d mail.Diagnosis
	return d, u.call(ctx, "mail.repair.check", nil, &d)
}

func (u uiClient) MailRepair(ctx context.Context, accept string) (mail.Repaired, error) {
	var r mail.Repaired
	return r, u.call(ctx, "mail.repair", mail.RepairAsk{Accept: accept}, &r)
}

func (u uiClient) MailSetupApply(ctx context.Context, accept string, open []int) error {
	return u.call(ctx, "mail.setup.apply", mail.Accept{Accept: accept, Open: open}, nil)
}

func (u uiClient) MailAddDomain(ctx context.Context, name string) error {
	return u.call(ctx, "mail.domain.add", mail.Name{Name: name}, nil)
}

func (u uiClient) MailRemoveDomain(ctx context.Context, name string) error {
	return u.call(ctx, "mail.domain.remove", mail.Name{Name: name}, nil)
}

func (u uiClient) MailRecords(ctx context.Context, domain string) (mail.RecordsAnswer, error) {
	var r mail.RecordsAnswer
	return r, u.call(ctx, "mail.records", mail.DomainAsk{Domain: domain}, &r)
}

func (u uiClient) MailTakeover(ctx context.Context, domain, name, typ string) error {
	return u.call(ctx, "mail.records.takeover", mail.TakeoverAsk{Domain: domain, Name: name, Type: typ}, nil)
}

func (u uiClient) MailSync(ctx context.Context) error {
	return u.call(ctx, "mail.sync", nil, nil)
}

func (u uiClient) MailAccounts(ctx context.Context, domain string) ([]mail.AccountView, error) {
	var as []mail.AccountView
	return as, u.call(ctx, "mail.account.list", mail.DomainAsk{Domain: domain}, &as)
}

func (u uiClient) MailAddAccount(ctx context.Context, address string, quota int64) error {
	return u.call(ctx, "mail.account.add", mail.AccountAsk{Address: address, Quota: quota}, nil)
}

func (u uiClient) MailLockAccount(ctx context.Context, address string) error {
	return u.call(ctx, "mail.account.lock", mail.AccountAsk{Address: address}, nil)
}

func (u uiClient) MailAppPasswords(ctx context.Context, address string) ([]mail.AppPasswordView, error) {
	var ps []mail.AppPasswordView
	return ps, u.call(ctx, "mail.apppassword.list", mail.AppPasswordAsk{Address: address}, &ps)
}

func (u uiClient) MailAddAppPassword(ctx context.Context, address, description string) (mail.NewAppPassword, error) {
	var n mail.NewAppPassword
	return n, u.call(ctx, "mail.apppassword.add", mail.AppPasswordAsk{Address: address, Description: description}, &n)
}

func (u uiClient) MailKeepAppPassword(ctx context.Context, address, id string) error {
	return u.call(ctx, "mail.apppassword.keep", mail.AppPasswordAsk{Address: address, ID: id}, nil)
}

func (u uiClient) MailRevokeAppPassword(ctx context.Context, address, id string) error {
	return u.call(ctx, "mail.apppassword.revoke", mail.AppPasswordAsk{Address: address, ID: id}, nil)
}

func (u uiClient) MailSetForward(ctx context.Context, address string, to []string, keep bool) (mail.AccountView, error) {
	var v mail.AccountView
	if to == nil {
		to = []string{}
	}
	return v, u.call(ctx, "mail.account.set", mail.AccountSet{Address: address, Forward: &mail.ForwardView{To: to, Keep: keep}}, &v)
}

func (u uiClient) MailSetAccount(ctx context.Context, address string, disabled *bool, aliases *[]string) (mail.AccountView, error) {
	var v mail.AccountView
	return v, u.call(ctx, "mail.account.set", mail.AccountSet{Address: address, Disabled: disabled, Aliases: aliases}, &v)
}

func (u uiClient) MailRemoveAccount(ctx context.Context, address string) error {
	return u.call(ctx, "mail.account.remove", mail.AccountAsk{Address: address}, nil)
}
