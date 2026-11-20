package ui

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/internal/cloudflare"
)

// MAIL — Mail › Set up mail, Domains, Accounts and Server: the mail verbs,
// in the panel's standard (two panes, access keys, no help text). Setting
// mail up writes the mail stack, and the stacks' own review applies it.
//
// Decision: docs/decisions/mail.md

// mailPanes are the mail panels' models and last answers.
type mailPanes struct {
	domains  *tuidecl.ListModel // App.mailDomains
	records  *tuidecl.ListModel // App.mailRecords: the selected domain's
	accounts *tuidecl.ListModel // App.mailAccounts
	apps     *tuidecl.ListModel // App.mailAppPasswords: the selected account's
	server   *tuidecl.ListModel // App.mailServerRows: Mail › Server's facts
	dns      *tuidecl.ListModel // App.dnsRows: the DNS records dialog's

	status mail.Status
	// The last Set up mail's answers: offered again when it is asked again,
	// since the daemon holds a setup only until it is applied.
	lastHost, lastDomain string
	statusRead           bool
	domainList           []string
	recordsOf            string
	recordList           []mail.RecordView
	dkimList             []mail.DKIMRow
	recordsAt            int64
	accountList          []mail.AccountView
	domainAt             int
	recordAt             int
	accountAt            int
	appsOf               string // the account appList is of
	appList              []mail.AppPasswordView
	appAt                int
	dnsList              []dnsRow
	dnsAt                int
}

func newMailPanes() mailPanes {
	return mailPanes{
		domains:  tuidecl.NewListModel("key", "name"),
		records:  tuidecl.NewListModel("key", "state", "type", "name"),
		accounts: tuidecl.NewListModel("key", "address", "quota", "used", "state"),
		apps:     tuidecl.NewListModel("key", "device", "made", "state"),
		server:   tuidecl.NewListModel("key", "label", "value"),
		dns:      tuidecl.NewListModel("key", "type", "host", "value"),
	}
}

func (d *mailPanes) state() map[string]any {
	return map[string]any{
		"App.mailDomains":           d.domains,
		"App.mailRecords":           d.records,
		"App.mailAccounts":          d.accounts,
		"App.mailAppPasswords":      d.apps,
		"App.mailAppPasswordsTitle": "",
		"App.appPwTitle":            "",
		"App.appPwText":             "",
		"App.appPwIntro":            "",
		"App.appPwNote":             "",
		"App.appPwCopyNote":         "",
		"App.appPwCopyShown":        false,
		"App.mailServerRows":        d.server,
		"App.mailCanOpenPorts":      false,
		"App.dnsRows":               d.dns,
		"App.dnsIntro":              "",
		"App.dnsDetail":             "",
		"App.dnsNote":               "",
		"App.dnsNoteShown":          false,
		"App.mailSetUp":             false,
		"App.mailNotSetUp":          true,
		"App.mailDomainsTitle":      "",
		"App.mailRecordsTitle":      "",
		"App.mailRecordDetail":      "",
		"App.mailAccountsTitle":     "",
		"App.mailAccountDetail":     "",
		"App.mailToggleText":        "",
		"App.mailServerTitle":       "",
		"App.secretTitle":           "",
		"App.secretText":            "",
		"App.secretLabel":           "",
		"App.secretError":           "",
		"App.secretErrorShown":      false,
	}
}

// --- reading ------------------------------------------------------------------

// loadMail reads mail's status, its domains, the selected domain's records and
// the accounts, and puts them on screen.
func (h *host) loadMail() {
	var (
		st       mail.Status
		recs     mail.RecordsAnswer
		accounts []mail.AccountView
		recErr   error
		accErr   error
	)
	want := h.mail.recordsOf
	h.background(func(ctx context.Context) error {
		var err error
		if st, err = h.client.MailStatus(ctx); err != nil {
			return err
		}
		if !st.SetUp {
			return nil
		}
		if want == "" && len(st.Domains) > 0 {
			want = st.Domains[0]
		}
		if want != "" {
			recs, recErr = h.client.MailRecords(ctx, want)
		}
		if st.Bootstrapped > 0 {
			accounts, accErr = h.client.MailAccounts(ctx, "")
		}
		return nil
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		h.mail.status, h.mail.statusRead = st, true
		// The domains, then the mail host: its own records (its address, its
		// SPF) are published as theirs are, and by hand without a DNS token.
		h.mail.domainList = append([]string(nil), st.Domains...)
		if st.Host != "" && !slices.Contains(st.Domains, st.Host) {
			h.mail.domainList = append(h.mail.domainList, st.Host)
		}
		h.mail.recordsOf = want
		if recErr == nil {
			h.mail.recordList, h.mail.dkimList, h.mail.recordsAt = recs.Records, recs.DKIM, recs.At
		}
		if accErr == nil {
			h.mail.accountList = accounts
		}
		h.renderMail()
		if accErr == nil && len(accounts) > 0 {
			h.loadAppPasswords()
		}
	})
}

// renderMail puts the mail panels' rows, titles and details on screen.
func (h *host) renderMail() {
	m := &h.mail
	rows := make([]tuidecl.Row, 0, len(m.domainList))
	for _, d := range m.domainList {
		label := d
		if d == m.status.Host {
			label = h.trf("autopanel.value.mail.hostRow", d)
		}
		rows = append(rows, tuidecl.Row{"key": d, "name": label})
	}
	m.domains.Reset(rows)
	rrows := make([]tuidecl.Row, 0, len(m.recordList))
	for i, r := range m.recordList {
		rrows = append(rrows, tuidecl.Row{"key": strconv.Itoa(i), "state": r.State, "type": r.Type, "name": r.Name})
	}
	m.records.Reset(rrows)
	arows := make([]tuidecl.Row, 0, len(m.accountList))
	for _, a := range m.accountList {
		state := ""
		if a.Disabled {
			state = h.tr("autopanel.value.mail.disabled")
		}
		arows = append(arows, tuidecl.Row{"key": a.Address, "address": a.Address, "quota": sizeText(a.Quota), "used": sizeText(a.Used), "state": state})
	}
	m.accounts.Reset(arows)
	m.server.Reset(h.mailServerRows())
	_ = h.p.Set("App.mailCanOpenPorts", len(h.mailBlockedPorts()) > 0)
	at := time.Now().Format("15:04:05")
	recTitle := h.tr("autopanel.title.list.mailRecords")
	if m.recordsOf != "" {
		recTitle += " · " + m.recordsOf
	}
	_ = h.p.SetMany(map[string]any{
		"App.mailSetUp":         m.status.SetUp,
		"App.mailNotSetUp":      h.mailMaySetUp(),
		"App.mailDomainsTitle":  h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.mailDomains"), len(m.status.Domains), at),
		"App.mailRecordsTitle":  recTitle,
		"App.mailRecordDetail":  h.mailRecordDetail(),
		"App.mailAccountsTitle": h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.mailAccounts"), len(m.accountList), at),
		"App.mailAccountDetail": h.mailAccountDetail(),
		"App.mailToggleText":    h.mailToggleText(),
		"App.mailServerTitle":   h.tr("autopanel.title.panel.mailServer") + " · " + at,
	})
}

// sizeText is a quota or a use: "-" for none, else bytesText's.
func sizeText(n int64) string {
	if n <= 0 {
		return "-"
	}
	return bytesText(uint64(n))
}

func (h *host) mailRecordDetail() string {
	m := &h.mail
	if !m.status.SetUp {
		return h.tr("autopanel.notice.mail.notSetUp")
	}
	var b strings.Builder
	if m.recordAt >= 0 && m.recordAt < len(m.recordList) {
		r := m.recordList[m.recordAt]
		pairs := [][2]string{
			{"autopanel.label.mail.why", orDash(r.Why)},
			{"autopanel.label.mail.state", r.State},
			{"autopanel.label.mail.value", r.Value},
		}
		if r.Found != "" {
			pairs = append(pairs, [2]string{"autopanel.label.mail.found", r.Found})
		}
		if r.Error != "" {
			pairs = append(pairs, [2]string{"autopanel.label.mail.error", r.Error})
		}
		b.WriteString(facts(h, pairs...))
	}
	if len(m.dkimList) > 0 {
		b.WriteString("\n\n" + h.tr("autopanel.label.mail.dkim"))
		for _, k := range m.dkimList {
			b.WriteString("\n  " + k.Selector + "  " + k.Step + "  " + time.Unix(k.Since, 0).Format("2006-01-02 15:04"))
		}
	}
	if m.recordsAt > 0 {
		b.WriteString("\n\n" + h.tr("autopanel.label.mail.synced") + "  " + time.Unix(m.recordsAt, 0).Format("2006-01-02 15:04:05"))
	}
	return b.String()
}

func (h *host) mailAccountDetail() string {
	m := &h.mail
	if m.accountAt < 0 || m.accountAt >= len(m.accountList) {
		return ""
	}
	a := m.accountList[m.accountAt]
	aliases := strings.Join(a.Aliases, ", ")
	return facts(h,
		[2]string{"autopanel.label.mail.address", a.Address},
		[2]string{"autopanel.label.mail.quota", sizeText(a.Quota)},
		[2]string{"autopanel.label.mail.used", sizeText(a.Used)},
		[2]string{"autopanel.label.mail.aliases", orDash(aliases)},
		[2]string{"autopanel.label.mail.signIn", accountState(h, a.Disabled)})
}

// mailServerRows are Mail › Server's facts, a row each (a problem a row of
// its own).
func (h *host) mailServerRows() []tuidecl.Row {
	s := h.mail.status
	row := func(i int, label, value string) tuidecl.Row {
		return tuidecl.Row{"key": strconv.Itoa(i), "label": h.tr(label), "value": value}
	}
	if !s.SetUp {
		return []tuidecl.Row{row(0, "autopanel.label.mail.state", h.tr("autopanel.notice.mail.notSetUp"))}
	}
	state := s.Step
	if s.Error != "" {
		state += " · " + s.Error
	}
	when := func(t int64) string {
		if t == 0 {
			return h.tr("autopanel.value.mail.never")
		}
		return time.Unix(t, 0).Format("2006-01-02 15:04:05")
	}
	rows := []tuidecl.Row{
		row(0, "autopanel.label.mail.host", s.Host),
		row(1, "autopanel.label.mail.state", orDash(state)),
		row(2, "autopanel.label.mail.stack", orDash(s.Stack)),
		row(3, "autopanel.label.mail.loopback", orDash(s.Loopback)),
		row(4, "autopanel.label.mail.certificate", orDash(s.Certificate)),
		row(5, "autopanel.label.mail.domains", orDash(strings.Join(s.Domains, ", "))),
		row(6, "autopanel.label.mail.synced", when(s.SyncedAt)),
	}
	for i, p := range s.Ports {
		label := ""
		if i == 0 {
			label = h.tr("autopanel.label.mail.ports")
		}
		value := p.Key + ": " + verdictText(h, p.Verdict)
		switch {
		case p.By == "other":
			value += " · " + h.tr("autopanel.value.firewall.byOther")
		case p.By != "":
			value += " · " + p.By
		case p.Needs && !p.Managed && len(p.Commands) > 0:
			value += " · " + strings.Join(p.Commands, "; ")
		}
		rows = append(rows, tuidecl.Row{"key": "p" + strconv.Itoa(i), "label": label, "value": value})
	}
	if len(s.SyncErrors) == 0 {
		return append(rows, row(7, "autopanel.label.mail.errors", h.tr("autopanel.value.mail.none")))
	}
	for i, e := range s.SyncErrors {
		label := ""
		if i == 0 {
			label = h.tr("autopanel.label.mail.errors")
		}
		rows = append(rows, tuidecl.Row{"key": strconv.Itoa(7 + i), "label": label, "value": e})
	}
	return rows
}

// mailBlockedPorts are mail's ports that need a rule AutoPanel can make.
func (h *host) mailBlockedPorts() []int {
	var out []int
	for _, p := range h.mail.status.Ports {
		if p.Needs && p.Managed {
			out = append(out, p.Want.From)
		}
	}
	return out
}

// mailOpenPorts is Open ports on Mail › Server: mail's ports that need a rule
// are opened, as mail's.
func (h *host) mailOpenPorts() error {
	ports := h.mailBlockedPorts()
	if len(ports) == 0 {
		return nil
	}
	h.change(func(ctx context.Context) error { return h.client.MailPortsOpen(ctx, ports) }, func() {
		h.say(h.tr("autopanel.notice.mail.portsOpened"))
		h.loadMail()
	})
	return nil
}

// --- opening ------------------------------------------------------------------

func (h *host) openMailDomains() error {
	h.loadMail()
	return h.openPanel("mailDomains")
}

func (h *host) openMailAccounts() error {
	h.loadMail()
	return h.openPanel("mailAccounts")
}

func (h *host) openMailServer() error {
	h.loadMail()
	return h.openPanel("mailServer")
}

func (h *host) mailDomainMoved(row int) error {
	h.mail.domainAt = row
	if row < 0 || row >= len(h.mail.domainList) || h.mail.domainList[row] == h.mail.recordsOf {
		return nil
	}
	h.mail.recordsOf, h.mail.recordAt = h.mail.domainList[row], 0
	h.loadMail()
	return nil
}

func (h *host) mailRecordMoved(row int) error {
	h.mail.recordAt = row
	return h.p.Set("App.mailRecordDetail", h.mailRecordDetail())
}

func (h *host) mailAccountMoved(row int) error {
	moved := row != h.mail.accountAt
	h.mail.accountAt = row
	if moved {
		h.mail.appAt = 0
		h.loadAppPasswords()
	}
	return h.p.SetMany(map[string]any{"App.mailAccountDetail": h.mailAccountDetail(), "App.mailToggleText": h.mailToggleText()})
}

// mailToggleText names what Disable/Enable would do to the selected account.
func (h *host) mailToggleText() string {
	m := &h.mail
	if m.accountAt >= 0 && m.accountAt < len(m.accountList) && m.accountList[m.accountAt].Disabled {
		return h.tr("autopanel.button.mail.enable")
	}
	return h.tr("autopanel.button.mail.disable")
}

// --- setting up ---------------------------------------------------------------

// mailSetup asks for the mail host, then the first domain, writes the mail
// stack, and opens its review: confirming it applies the stack, and Stalwart
// is set up once it runs.
// mailSetup reads mail's state first: a setup left at its review is taken
// again, its answers offered, and a setup Stalwart took is said, not asked.
func (h *host) mailSetup() error {
	var st mail.Status
	h.background(func(ctx context.Context) (err error) {
		st, err = h.client.MailStatus(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		h.mail.status = st
		_ = h.p.SetMany(map[string]any{"App.mailNotSetUp": h.mailMaySetUp()})
		if !h.mailMaySetUp() {
			h.say(h.tr("autopanel.notice.mail.setUp"))
			return
		}
		if err := h.askMailSetup(); err != nil {
			h.failed(err)
		}
	})
	return nil
}

// askMailSetup asks the mail host, then the first domain, then writes the
// stack and opens its review.
func (h *host) askMailSetup() error {
	first := ""
	if len(h.domains) > 0 {
		first = h.domains[0].Name
	}
	start := ""
	if first != "" {
		start = "mail." + first
	}
	if h.mail.lastHost != "" { // asked again: what was answered before
		start = h.mail.lastHost
	}
	return h.prompt("autopanel.title.prompt.mailHost", "autopanel.label.prompt.mailHost", start, func(host string) error {
		host = strings.ToLower(strings.TrimSpace(host))
		if !strings.Contains(host, ".") {
			h.promptRefused(h.tr("autopanel.notice.mail.badHost"))
			return nil
		}
		domain := ""
		for _, d := range h.domains {
			if host == d.Name || strings.HasSuffix(host, "."+d.Name) {
				domain = d.Name
			}
		}
		if h.mail.lastDomain != "" && host == h.mail.lastHost {
			domain = h.mail.lastDomain
		}
		h.promptDone()
		return h.prompt("autopanel.title.prompt.mailDomain", "autopanel.label.prompt.mailDomain", domain, func(domain string) error {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if h.busy {
				h.promptRefused(h.tr("autopanel.notice.app.busy"))
				return nil
			}
			h.busy = true
			var out mail.Setup
			h.background(func(ctx context.Context) (err error) {
				out, err = h.client.MailSetup(ctx, host, domain)
				return err
			}, func(err error) {
				h.busy = false
				switch {
				case errors.Is(err, mail.ErrNotRegistered):
					h.promptRefused(h.trf("autopanel.notice.mail.notRegistered", domain))
				case errors.Is(err, mail.ErrSetUp):
					h.promptDone()
					h.say(h.tr("autopanel.notice.mail.setUp"))
				case err != nil:
					h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
				default:
					h.promptDone()
					h.mail.lastHost, h.mail.lastDomain = host, domain
					h.stk.nextDraft = true          // Add and start applies the setup: nothing is written before it
					out.Review.Firewall = out.Ports // mail's four ports, ticked when they need a rule
					if err := h.showReview(mail.Stack, reviewAdd, out.Review, false); err != nil {
						h.failed(err)
					}
				}
			})
			return nil
		})
	})
}

// runMailSetup is Add and start on the mail stack's review: the daemon makes
// the whole setup in one call, or undoes what it began.
func (h *host) runMailSetup(accept string, open []int) {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return
	}
	h.busy = true
	h.say(h.trf("autopanel.notice.stacks.working", mail.Stack))
	h.background(func(ctx context.Context) error { return h.client.MailSetupApply(ctx, accept, open) }, func(err error) {
		h.busy = false
		switch {
		case errors.Is(err, mail.ErrChanged), errors.Is(err, mail.ErrNoPending):
			h.say(h.tr("autopanel.notice.mail.setUpAgain"))
		case err != nil:
			h.failed(err)
		default:
			h.mail.lastHost, h.mail.lastDomain = "", ""
			h.say(h.tr("autopanel.notice.mail.applied"))
		}
		h.loadMail()
		h.loadStacks()
	})
}

// --- domains ------------------------------------------------------------------

// mailMaySetUp says whether Mail → Set up mail is open: before mail is set
// up, and over what a v0.2.6 setup left at its review (recorded, its stack
// never added, Stalwart never set up), which mail.setup drops.
func (h *host) mailMaySetUp() bool {
	st := h.mail.status
	return !st.SetUp || (st.Bootstrapped == 0 && st.Stack == "absent")
}

func (h *host) mailReady() bool {
	switch {
	case !h.mail.status.SetUp:
		h.say(h.tr("autopanel.notice.mail.notSetUp"))
		return false
	case h.mail.status.Bootstrapped == 0:
		h.say(h.tr("autopanel.notice.mail.notReady"))
		return false
	}
	return true
}

func (h *host) mailAddDomain() error {
	if !h.mailReady() {
		return nil
	}
	return h.prompt("autopanel.title.prompt.mailAddDomain", "autopanel.label.prompt.mailAddDomain", "", func(name string) error {
		name = strings.ToLower(strings.TrimSpace(name))
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error { return h.client.MailAddDomain(ctx, name) }, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, mail.ErrNotRegistered):
				h.promptRefused(h.trf("autopanel.notice.mail.notRegistered", name))
			case err != nil:
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
			default:
				h.promptDone()
				h.say(h.trf("autopanel.notice.mail.domainAdded", name))
				h.mail.recordsOf = name
				h.loadMail()
			}
		})
		return nil
	})
}

func (h *host) mailRemoveDomain(row int) error {
	if row < 0 || row >= len(h.mail.domainList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	name := h.mail.domainList[row]
	if name == h.mail.status.Host {
		h.say(h.tr("autopanel.notice.mail.isHost"))
		return nil
	}
	return h.ask("autopanel.title.confirm.mailRemoveDomain", h.trf("autopanel.question.mail.removeDomain", name), func() error {
		h.change(func(ctx context.Context) error { return h.client.MailRemoveDomain(ctx, name) }, func() {
			h.say(h.trf("autopanel.notice.mail.domainRemoved", name))
			if h.mail.recordsOf == name {
				h.mail.recordsOf = ""
			}
			h.loadMail()
		})
		return nil
	})
}

func (h *host) mailTakeover(row int) error {
	if row < 0 || row >= len(h.mail.recordList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	r, domain := h.mail.recordList[row], h.mail.recordsOf
	if r.State != "different" {
		h.say(h.tr("autopanel.notice.mail.noRecord"))
		return nil
	}
	return h.ask("autopanel.title.confirm.mailTakeover", h.trf("autopanel.question.mail.takeover", r.Type, r.Name, r.Found, r.Value), func() error {
		h.change(func(ctx context.Context) error { return h.client.MailTakeover(ctx, domain, r.Name, r.Type) }, func() {
			h.say(h.trf("autopanel.notice.mail.takenOver", r.Type+" "+r.Name))
			h.later(5*time.Second, h.loadMail)
		})
		return nil
	})
}

func (h *host) mailSync() error {
	if !h.mailReady() {
		return nil
	}
	h.change(func(ctx context.Context) error { return h.client.MailSync(ctx) }, func() {
		h.say(h.tr("autopanel.notice.mail.syncing"))
		h.later(15*time.Second, h.loadMail)
	})
	return nil
}

func (h *host) mailReload() error {
	h.loadMail()
	return nil
}

// later runs fn on the loop after d.
func (h *host) later(d time.Duration, fn func()) {
	go func() {
		select {
		case <-h.ctx.Done():
		case <-time.After(d):
			h.p.Post(fn)
		}
	}()
}

// --- accounts -----------------------------------------------------------------

func (h *host) mailAddAccount() error {
	if !h.mailReady() {
		return nil
	}
	start := ""
	if len(h.mail.domainList) > 0 {
		start = "@" + h.mail.domainList[0]
	}
	return h.prompt("autopanel.title.prompt.mailAccount", "autopanel.label.prompt.mailAccount", start, func(addr string) error {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if !strings.Contains(addr, "@") || strings.HasPrefix(addr, "@") {
			h.promptRefused(h.tr("autopanel.notice.mail.badAddress"))
			return nil
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		// The account's own password is generated by the daemon and told to
		// no one: its devices sign in with app passwords, offered next.
		h.background(func(ctx context.Context) error { return h.client.MailAddAccount(ctx, addr, 0) }, func(err error) {
			h.busy = false
			if err != nil {
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
				return
			}
			h.promptDone()
			h.say(h.trf("autopanel.notice.mail.accountAdded", addr))
			h.loadMail()
			_ = h.ask("autopanel.title.confirm.appFirst", h.trf("autopanel.question.mail.appFirst", addr), func() error {
				return h.addAppPasswordFor(addr)
			})
		})
		return nil
	})
}

// accountState is whether an account signs in, in words.
func accountState(h *host, disabled bool) string {
	if disabled {
		return h.tr("autopanel.value.mail.disabledLong")
	}
	return h.tr("autopanel.value.mail.enabled")
}

// mailToggleAccount disables the selected account, after asking, or enables
// it again.
func (h *host) mailToggleAccount(row int) error {
	if row < 0 || row >= len(h.mail.accountList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	a := h.mail.accountList[row]
	addr, disable := a.Address, !a.Disabled
	set := func() error {
		h.change(func(ctx context.Context) error {
			_, err := h.client.MailSetAccount(ctx, addr, &disable, nil)
			return err
		}, func() {
			if disable {
				h.say(h.trf("autopanel.notice.mail.accountDisabled", addr))
			} else {
				h.say(h.trf("autopanel.notice.mail.accountEnabled", addr))
			}
			h.loadMail()
		})
		return nil
	}
	if !disable {
		return set()
	}
	return h.ask("autopanel.title.confirm.mailDisable", h.trf("autopanel.question.mail.disable", addr), set)
}

// mailAccountAliases edits the selected account's aliases as one line of
// addresses; an empty line removes them all.
func (h *host) mailAccountAliases(row int) error {
	if row < 0 || row >= len(h.mail.accountList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	a := h.mail.accountList[row]
	addr := a.Address
	return h.prompt("autopanel.title.prompt.mailAliases", "autopanel.label.prompt.mailAliases", strings.Join(a.Aliases, ", "), func(text string) error {
		aliases := []string{}
		for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			aliases = append(aliases, strings.ToLower(f))
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		kept := 0 // as the server answered, after it dropped duplicates
		h.background(func(ctx context.Context) error {
			v, err := h.client.MailSetAccount(ctx, addr, nil, &aliases)
			kept = len(v.Aliases)
			return err
		}, func(err error) {
			h.busy = false
			if err != nil {
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
				return
			}
			h.promptDone()
			h.say(h.trf("autopanel.notice.mail.aliasesSet", addr, kept))
			h.loadMail()
		})
		return nil
	})
}

func (h *host) mailRemoveAccount(row int) error {
	if row < 0 || row >= len(h.mail.accountList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	addr := h.mail.accountList[row].Address
	return h.ask("autopanel.title.confirm.mailRemoveAccount", h.trf("autopanel.question.mail.removeAccount", addr), func() error {
		h.change(func(ctx context.Context) error { return h.client.MailRemoveAccount(ctx, addr) }, func() {
			h.say(h.trf("autopanel.notice.mail.accountRemoved", addr))
			h.loadMail()
		})
		return nil
	})
}

// --- the secret dialog: a password, typed unseen ----------------------------------

// askSecret opens the password dialog. then gets the text once OK is pressed
// with one long enough; it runs with h.busy set, and must answer through
// secretAnswered. The text is never put in a source or a log.
func (h *host) askSecret(title, label string, then func(string)) error {
	h.secreted = then
	h.secretShort = "autopanel.notice.mail.weakPassword"
	if err := h.fill(map[string]any{"App.secretText": ""}); err != nil { // the field starts empty, every time
		return err
	}
	if err := h.p.SetMany(map[string]any{"App.secretTitle": title, "App.secretLabel": label,
		"App.secretError": "", "App.secretErrorShown": false}); err != nil {
		return err
	}
	return h.p.Call("secretDialog", "open")
}

// secretEntered is OK in the password dialog.
func (h *host) secretEntered(text string) error {
	if h.secreted == nil {
		return h.p.Call("secretDialog", "close")
	}
	if n := len([]rune(text)); n < 12 || n > 256 {
		return h.p.SetMany(map[string]any{"App.secretError": h.tr(h.secretShort), "App.secretErrorShown": true})
	}
	if h.busy {
		return h.p.SetMany(map[string]any{"App.secretError": h.tr("autopanel.notice.app.busy"), "App.secretErrorShown": true})
	}
	h.busy = true
	h.secreted(text)
	return nil
}

// secretAnswered closes the password dialog after a success, or says why in it.
func (h *host) secretAnswered(err error, done func()) {
	if err != nil {
		msg := h.trf("autopanel.notice.app.error", err.Error())
		switch {
		case errors.Is(err, cloudflare.ErrTokenRefused):
			msg = h.tr("autopanel.notice.certs.cloudflareRefused")
		case errors.Is(err, cloudflare.ErrNoAnswer):
			msg = h.tr("autopanel.notice.certs.cloudflareNoAnswer")
		}
		_ = h.p.SetMany(map[string]any{"App.secretError": msg, "App.secretErrorShown": true})
		return
	}
	h.secreted = nil
	_ = h.p.Call("secretDialog", "close")
	done()
}

// --- the DNS records dialog: what to enter at a DNS provider -------------------

// dnsRow is one record of the dialog, with the zone its host is relative to.
type dnsRow struct {
	zone string
	rec  mail.RecordView
}

// openDNSRecords reads the records of every mail domain and of the mail host,
// and shows them as a DNS provider asks for them: each host relative to its
// zone ("@" for the zone itself), each value whole.
func (h *host) openDNSRecords() error {
	st := h.mail.status
	if !st.SetUp {
		h.say(h.tr("autopanel.notice.mail.notSetUp"))
		return nil
	}
	owners := append([]string(nil), st.Domains...)
	if st.Host != "" && !slices.Contains(owners, st.Host) {
		owners = append(owners, st.Host)
	}
	got := map[string]mail.RecordsAnswer{}
	h.background(func(ctx context.Context) error {
		for _, o := range owners {
			r, err := h.client.MailRecords(ctx, o)
			if err != nil {
				return err
			}
			got[o] = r
		}
		return nil
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		var list []dnsRow
		manual := false
		for _, o := range owners {
			zone := o
			if o == st.Host {
				zone = zoneOf(o, st.Domains, h.domains)
			}
			for _, r := range got[o].Records {
				list = append(list, dnsRow{zone: zone, rec: r})
				manual = manual || r.State == "manual"
			}
		}
		h.mail.dnsList, h.mail.dnsAt = list, 0
		rows := make([]tuidecl.Row, 0, len(list))
		for i, d := range list {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "type": d.rec.Type, "host": relHost(d.rec.Name, d.zone), "value": d.rec.Value})
		}
		h.mail.dns.Reset(rows)
		intro := h.tr("autopanel.label.mail.dnsIntro")
		if !manual && len(list) > 0 {
			intro = h.tr("autopanel.label.mail.dnsAuto")
		}
		if len(list) == 0 {
			intro = h.tr("autopanel.notice.mail.notReady")
		}
		_ = h.p.SetMany(map[string]any{"App.dnsIntro": intro, "App.dnsDetail": h.dnsDetail(), "App.dnsNote": "", "App.dnsNoteShown": false})
		_ = h.p.Call("dnsDialog", "open")
	})
	return nil
}

// zoneOf is the zone a name is in: the longest mail or registry domain it is
// under, or its parent.
func zoneOf(name string, mailDomains []string, registry []gate.DomainView) string {
	best := ""
	consider := func(d string) {
		if (name == d || strings.HasSuffix(name, "."+d)) && len(d) > len(best) {
			best = d
		}
	}
	for _, d := range mailDomains {
		consider(d)
	}
	for _, d := range registry {
		consider(d.Name)
	}
	if best == "" {
		if _, parent, ok := strings.Cut(name, "."); ok {
			return parent
		}
		return name
	}
	return best
}

// relHost is a name as a DNS provider's Host field takes it: without its zone,
// or "@" for the zone itself.
func relHost(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// dnsDetail is the selected record whole, its fields split as a provider's form
// asks for an MX or an SRV record.
func (h *host) dnsDetail() string {
	m := &h.mail
	if m.dnsAt < 0 || m.dnsAt >= len(m.dnsList) {
		return ""
	}
	d := m.dnsList[m.dnsAt]
	pairs := [][2]string{
		{"autopanel.label.mail.zone", d.zone},
		{"autopanel.label.mail.type", d.rec.Type},
		{"autopanel.label.mail.hostName", relHost(d.rec.Name, d.zone)},
	}
	f := strings.Fields(d.rec.Value)
	switch {
	case d.rec.Type == "MX" && len(f) == 2:
		pairs = append(pairs, [2]string{"autopanel.label.mail.priority", f[0]}, [2]string{"autopanel.label.mail.target", f[1]})
	case d.rec.Type == "SRV" && len(f) == 4:
		service, proto, _ := strings.Cut(relHost(d.rec.Name, d.zone), ".")
		proto, _, _ = strings.Cut(proto, ".")
		pairs = append(pairs, [2]string{"autopanel.label.mail.service", service}, [2]string{"autopanel.label.mail.protocol", proto},
			[2]string{"autopanel.label.mail.priority", f[0]}, [2]string{"autopanel.label.mail.weight", f[1]},
			[2]string{"autopanel.label.mail.port", f[2]}, [2]string{"autopanel.label.mail.target", f[3]})
	default:
		pairs = append(pairs, [2]string{"autopanel.label.mail.value", d.rec.Value})
	}
	pairs = append(pairs, [2]string{"autopanel.label.mail.why", orDash(d.rec.Why)}, [2]string{"autopanel.label.mail.state", d.rec.State})
	return facts(h, pairs...)
}

func (h *host) dnsMoved(row int) error {
	h.mail.dnsAt = row
	return h.p.Set("App.dnsDetail", h.dnsDetail())
}

// dnsCopy puts the selected record's value on the clipboard, through the
// terminal (OSC 52); a terminal that takes none is said so.
func (h *host) dnsCopy(row int) error {
	if row < 0 || row >= len(h.mail.dnsList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	// Said in the dialog: the status bar is under it.
	note := h.tr("autopanel.notice.mail.noClipboard")
	if app := h.p.App(); app != nil && app.CopyToClipboard(h.mail.dnsList[row].rec.Value) {
		note = h.tr("autopanel.notice.mail.copied")
	}
	return h.p.SetMany(map[string]any{"App.dnsNote": note, "App.dnsNoteShown": true})
}
