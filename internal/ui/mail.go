package ui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/mail"
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
	server   *tuidecl.ListModel // App.mailServerRows: Mail › Server\'s facts

	status      mail.Status
	statusRead  bool
	domainList  []string
	recordsOf   string
	recordList  []mail.RecordView
	dkimList    []mail.DKIMRow
	recordsAt   int64
	accountList []mail.AccountView
	domainAt    int
	recordAt    int
	accountAt   int
}

func newMailPanes() mailPanes {
	return mailPanes{
		domains:  tuidecl.NewListModel("key", "name"),
		records:  tuidecl.NewListModel("key", "state", "type", "name"),
		accounts: tuidecl.NewListModel("key", "address", "quota", "used"),
		server:   tuidecl.NewListModel("key", "label", "value"),
	}
}

func (d *mailPanes) state() map[string]any {
	return map[string]any{
		"App.mailDomains":       d.domains,
		"App.mailRecords":       d.records,
		"App.mailAccounts":      d.accounts,
		"App.mailServerRows":    d.server,
		"App.mailSetUp":         false,
		"App.mailNotSetUp":      true,
		"App.mailDomainsTitle":  "",
		"App.mailRecordsTitle":  "",
		"App.mailRecordDetail":  "",
		"App.mailAccountsTitle": "",
		"App.mailAccountDetail": "",
		"App.mailServerTitle":   "",
		"App.secretTitle":       "",
		"App.secretText":        "",
		"App.secretLabel":       "",
		"App.secretError":       "",
		"App.secretErrorShown":  false,
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
		h.mail.domainList = st.Domains
		h.mail.recordsOf = want
		if recErr == nil {
			h.mail.recordList, h.mail.dkimList, h.mail.recordsAt = recs.Records, recs.DKIM, recs.At
		}
		if accErr == nil {
			h.mail.accountList = accounts
		}
		h.renderMail()
	})
}

// renderMail puts the mail panels' rows, titles and details on screen.
func (h *host) renderMail() {
	m := &h.mail
	rows := make([]tuidecl.Row, 0, len(m.domainList))
	for _, d := range m.domainList {
		rows = append(rows, tuidecl.Row{"key": d, "name": d})
	}
	m.domains.Reset(rows)
	rrows := make([]tuidecl.Row, 0, len(m.recordList))
	for i, r := range m.recordList {
		rrows = append(rrows, tuidecl.Row{"key": strconv.Itoa(i), "state": r.State, "type": r.Type, "name": r.Name})
	}
	m.records.Reset(rrows)
	arows := make([]tuidecl.Row, 0, len(m.accountList))
	for _, a := range m.accountList {
		arows = append(arows, tuidecl.Row{"key": a.Address, "address": a.Address, "quota": sizeText(a.Quota), "used": sizeText(a.Used)})
	}
	m.accounts.Reset(arows)
	m.server.Reset(h.mailServerRows())
	at := time.Now().Format("15:04:05")
	recTitle := h.tr("autopanel.title.list.mailRecords")
	if m.recordsOf != "" {
		recTitle += " · " + m.recordsOf
	}
	_ = h.p.SetMany(map[string]any{
		"App.mailSetUp":         m.status.SetUp,
		"App.mailNotSetUp":      !m.status.SetUp,
		"App.mailDomainsTitle":  h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.mailDomains"), len(m.domainList), at),
		"App.mailRecordsTitle":  recTitle,
		"App.mailRecordDetail":  h.mailRecordDetail(),
		"App.mailAccountsTitle": h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.mailAccounts"), len(m.accountList), at),
		"App.mailAccountDetail": h.mailAccountDetail(),
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
		[2]string{"autopanel.label.mail.aliases", orDash(aliases)})
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
	h.mail.accountAt = row
	return h.p.Set("App.mailAccountDetail", h.mailAccountDetail())
}

// --- setting up ---------------------------------------------------------------

// mailSetup asks for the mail host, then the first domain, writes the mail
// stack, and opens its review: confirming it applies the stack, and Stalwart
// is set up once it runs.
func (h *host) mailSetup() error {
	first := ""
	if len(h.domains) > 0 {
		first = h.domains[0].Name
	}
	start := ""
	if first != "" {
		start = "mail." + first
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
		h.promptDone()
		return h.prompt("autopanel.title.prompt.mailDomain", "autopanel.label.prompt.mailDomain", domain, func(domain string) error {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if h.busy {
				h.promptRefused(h.tr("autopanel.notice.app.busy"))
				return nil
			}
			h.busy = true
			h.background(func(ctx context.Context) error {
				_, err := h.client.MailSetup(ctx, host, domain)
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
					h.say(h.tr("autopanel.notice.mail.written"))
					h.loadMail()
					h.checkStack(mail.Stack, reviewAdd, false)
				}
			})
			return nil
		})
	})
}

// --- domains ------------------------------------------------------------------

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
		h.promptDone()
		return h.askSecret(h.tr("autopanel.title.prompt.mailPassword"), h.trf("autopanel.label.prompt.mailPassword", addr), func(pw string) {
			h.background(func(ctx context.Context) error { return h.client.MailAddAccount(ctx, addr, pw, 0) }, func(err error) {
				h.busy = false
				h.secretAnswered(err, func() {
					h.say(h.trf("autopanel.notice.mail.accountAdded", addr))
					h.loadMail()
				})
			})
		})
	})
}

func (h *host) mailAccountPassword(row int) error {
	if row < 0 || row >= len(h.mail.accountList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	addr := h.mail.accountList[row].Address
	return h.askSecret(h.tr("autopanel.title.prompt.mailPassword"), h.trf("autopanel.label.prompt.mailPassword", addr), func(pw string) {
		h.background(func(ctx context.Context) error { return h.client.MailSetPassword(ctx, addr, pw) }, func(err error) {
			h.busy = false
			h.secretAnswered(err, func() { h.say(h.trf("autopanel.notice.mail.passwordSet", addr)) })
		})
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
		return h.p.SetMany(map[string]any{"App.secretError": h.tr("autopanel.notice.mail.weakPassword"), "App.secretErrorShown": true})
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
		if errors.Is(err, mail.ErrWeakPassword) {
			msg = h.tr("autopanel.notice.mail.weakPassword")
		}
		_ = h.p.SetMany(map[string]any{"App.secretError": msg, "App.secretErrorShown": true})
		return
	}
	h.secreted = nil
	_ = h.p.Call("secretDialog", "close")
	done()
}
