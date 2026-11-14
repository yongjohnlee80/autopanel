package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/ui"
)

// uiClient is the TUI's Client over the control socket: every call is a verb.
// The panel's login dialog logs the connection in (Login); until then the
// service refuses every other verb.
type uiClient struct{ c *hostcontrol.Client }

// publicErrors are the errors the panel tells apart by their wire codes: the
// stacks', the routes' and mail's.
var publicErrors = slices.Concat((&services.Module{}).Errors(), (&gate.Module{}).Errors(), (&mail.Module{}).Errors())

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

func (u uiClient) Login(ctx context.Context, user, passphrase string) error {
	return u.call(ctx, "auth.login", auth.Login{User: user, Passphrase: passphrase}, nil)
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

func (u uiClient) Domains(ctx context.Context) ([]gate.DomainView, error) {
	var ds []gate.DomainView
	return ds, u.call(ctx, "gate.domain.list", nil, &ds)
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

func (u uiClient) ApplyStack(ctx context.Context, verb, name, accept string) error {
	switch verb {
	case "prepare", "add", "apply":
	default:
		return fmt.Errorf("no apply verb %q", verb)
	}
	// services.changed is told apart: the panel reviews the definition again.
	return u.call(ctx, "services."+verb, services.Accept{Name: name, Accept: accept}, nil)
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

func (u uiClient) MailSetup(ctx context.Context, host, domain string) (mail.Setup, error) {
	var s mail.Setup
	return s, u.call(ctx, "mail.setup", mail.SetupAsk{Host: host, Domain: domain}, &s)
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

func (u uiClient) MailAddAccount(ctx context.Context, address, password string, quota int64) error {
	return u.call(ctx, "mail.account.add", mail.AccountAsk{Address: address, Password: password, Quota: quota}, nil)
}

func (u uiClient) MailSetPassword(ctx context.Context, address, password string) error {
	return u.call(ctx, "mail.account.password", mail.AccountAsk{Address: address, Password: password}, nil)
}

func (u uiClient) MailRemoveAccount(ctx context.Context, address string) error {
	return u.call(ctx, "mail.account.remove", mail.AccountAsk{Address: address}, nil)
}
