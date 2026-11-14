package ui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// USERS AND ONE'S OWN ACCOUNT — Users › Users (admins), and Users › Passphrase,
// Two-factor and API tokens (everyone). A passphrase is typed in the password
// dialog; a secret shown once (a two-factor seed, recovery codes, a new token)
// is shown in a dialog that says so, and is in no source once it closes.
//
// Decision: docs/decisions/auth.md

type accountPanes struct {
	users  *tuidecl.ListModel // App.users
	tokens *tuidecl.ListModel // App.tokens

	userList    []auth.UserView
	tokenList   []auth.TokenView
	userAt      int
	tokenAt     int
	adminNoTOTP bool   // an enabled admin has no two-factor: said above the details (D2)
	newPass     string // the new passphrase between its two typings, cleared after
}

func newAccountPanes() accountPanes {
	return accountPanes{
		users:  tuidecl.NewListModel("key", "name", "role", "factor", "state"),
		tokens: tuidecl.NewListModel("key", "id", "name", "role", "owner", "expires"),
	}
}

func (a *accountPanes) state() map[string]any {
	return map[string]any{
		"App.users": a.users, "App.tokens": a.tokens,
		"App.usersTitle": "", "App.userDetail": "", "App.tokensTitle": "", "App.tokenDetail": "",
		"App.totpText": "", "App.totpError": "", "App.totpErrorShown": false, "App.totpCode": "",
		"App.onceTitle": "", "App.onceText": "",
	}
}

func day(t int64) string {
	if t == 0 {
		return "-"
	}
	return time.Unix(t, 0).Format("2006-01-02")
}

// --- users --------------------------------------------------------------------

func (h *host) openUsers() error {
	if !h.me.Root && h.me.Role != auth.RoleAdmin {
		h.say(h.tr("autopanel.notice.account.adminOnly"))
		return nil
	}
	h.loadUsers()
	return h.openPanel("users")
}

func (h *host) loadUsers() {
	var us []auth.UserView
	h.background(func(ctx context.Context) (err error) { us, err = h.client.Users(ctx); return err }, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		a := &h.acct
		a.userList = us
		rows := make([]tuidecl.Row, 0, len(us))
		for _, u := range us {
			factor, state := "-", "ok"
			if u.TOTP {
				factor = "2FA"
			}
			switch {
			case u.Disabled:
				state = h.tr("autopanel.value.account.disabled")
			case u.LockedUntil > time.Now().Unix():
				state = h.tr("autopanel.value.account.locked")
			case u.MustChange:
				state = h.tr("autopanel.value.account.mustChange")
			}
			rows = append(rows, tuidecl.Row{"key": u.Name, "name": u.Name, "role": string(u.Role), "factor": factor, "state": state})
		}
		a.users.Reset(rows)
		a.adminNoTOTP = false
		for _, u := range us {
			if u.Role == auth.RoleAdmin && !u.TOTP && !u.Disabled { // D2: said while any admin has none
				a.adminNoTOTP = true
			}
		}
		_ = h.p.SetMany(map[string]any{
			"App.usersTitle": h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.users"), len(us), time.Now().Format("15:04:05")),
			"App.userDetail": h.userDetail(),
		})
	})
}

func (h *host) userDetail() string {
	a := &h.acct
	if a.userAt < 0 || a.userAt >= len(a.userList) {
		return ""
	}
	u := a.userList[a.userAt]
	text := facts(h,
		[2]string{"autopanel.label.account.name", u.Name},
		[2]string{"autopanel.label.account.role", string(u.Role)},
		[2]string{"autopanel.label.account.factor", map[bool]string{true: h.tr("autopanel.value.account.enrolled"), false: "-"}[u.TOTP]},
		[2]string{"autopanel.label.account.lastLogin", day(u.LastLoginAt)},
		[2]string{"autopanel.label.account.lockedUntil", map[bool]string{true: time.Unix(u.LockedUntil, 0).Format("15:04"), false: "-"}[u.LockedUntil > time.Now().Unix()]})
	if u.Root {
		text += "\n\n" + h.tr("autopanel.note.account.root")
	}
	if a.adminNoTOTP {
		text = "⚠ " + h.tr("autopanel.note.account.adminNoTotp") + "\n\n" + text
	}
	return text
}

func (h *host) userMoved(row int) error {
	h.acct.userAt = row
	return h.p.Set("App.userDetail", h.userDetail())
}

func (h *host) userAt(row int) (auth.UserView, bool) {
	if row < 0 || row >= len(h.acct.userList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return auth.UserView{}, false
	}
	return h.acct.userList[row], true
}

// askRole asks a role by its name.
func (h *host) askRole(start string, then func(auth.Role)) error {
	return h.prompt("autopanel.title.prompt.userRole", "autopanel.label.prompt.userRole", start, func(text string) error {
		r := auth.Role(strings.ToLower(strings.TrimSpace(text)))
		if !r.Valid() {
			h.promptRefused(h.tr("autopanel.notice.account.badRole"))
			return nil
		}
		h.promptDone()
		then(r)
		return nil
	})
}

func (h *host) userAdd() error {
	return h.prompt("autopanel.title.prompt.userName", "autopanel.label.prompt.userName", "", func(name string) error {
		name = strings.ToLower(strings.TrimSpace(name))
		if !auth.ValidName(name) {
			h.promptRefused(h.tr("autopanel.notice.account.badName"))
			return nil
		}
		h.promptDone()
		return h.askRole("viewer", func(role auth.Role) {
			_ = h.askSecret(h.tr("autopanel.title.prompt.userPassphrase"), h.trf("autopanel.label.prompt.userPassphrase", name), func(pw string) {
				h.background(func(ctx context.Context) error { return h.client.UserAdd(ctx, name, string(role), pw) }, func(err error) {
					h.busy = false
					h.secretAnswered(accountErr(err), func() {
						h.say(h.trf("autopanel.notice.account.added", name))
						h.loadUsers()
					})
				})
			})
		})
	})
}

func (h *host) userRole(row int) error {
	u, ok := h.userAt(row)
	if !ok {
		return nil
	}
	return h.askRole(string(u.Role), func(role auth.Role) {
		_ = h.askSecret(h.tr("autopanel.title.prompt.userPassphrase"), h.trf("autopanel.label.prompt.userReset", u.Name), func(pw string) {
			h.background(func(ctx context.Context) error { return h.client.UserRole(ctx, u.Name, string(role), pw) }, func(err error) {
				h.busy = false
				h.secretAnswered(accountErr(err), func() {
					h.say(h.trf("autopanel.notice.account.roleSet", u.Name, string(role)))
					h.loadUsers()
				})
			})
		})
	})
}

func (h *host) userReset(row int) error {
	u, ok := h.userAt(row)
	if !ok {
		return nil
	}
	return h.askSecret(h.tr("autopanel.title.prompt.userPassphrase"), h.trf("autopanel.label.prompt.userReset", u.Name), func(pw string) {
		h.background(func(ctx context.Context) error { return h.client.UserReset(ctx, u.Name, pw) }, func(err error) {
			h.busy = false
			h.secretAnswered(accountErr(err), func() { h.say(h.trf("autopanel.notice.account.reset", u.Name)); h.loadUsers() })
		})
	})
}

func (h *host) userDisable(row int) error {
	u, ok := h.userAt(row)
	if !ok {
		return nil
	}
	to := !u.Disabled
	h.change(func(ctx context.Context) error { return h.client.UserDisable(ctx, u.Name, to) }, func() {
		h.say(h.trf(map[bool]string{true: "autopanel.notice.account.disabled", false: "autopanel.notice.account.enabled"}[to], u.Name))
		h.loadUsers()
	})
	return nil
}

func (h *host) userUnlock(row int) error {
	u, ok := h.userAt(row)
	if !ok {
		return nil
	}
	h.change(func(ctx context.Context) error { return h.client.UserUnlock(ctx, u.Name) }, func() {
		h.say(h.trf("autopanel.notice.account.unlocked", u.Name))
		h.loadUsers()
	})
	return nil
}

func (h *host) userRemove(row int) error {
	u, ok := h.userAt(row)
	if !ok {
		return nil
	}
	return h.ask("autopanel.title.confirm.userRemove", h.trf("autopanel.question.account.remove", u.Name), func() error {
		h.change(func(ctx context.Context) error { return h.client.UserRemove(ctx, u.Name) }, func() {
			h.say(h.trf("autopanel.notice.account.removed", u.Name))
			h.loadUsers()
		})
		return nil
	})
}

// accountErr makes a daemon's refusal readable in the password dialog.
func accountErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrWeak):
		return errors.New("a passphrase is 12 characters at least, holds no user name, and is no common password")
	case errors.Is(err, auth.ErrVaultLocked):
		return errors.New("an admin needs the vault open: log in as an admin first")
	}
	return err
}

// --- the passphrase -----------------------------------------------------------

// changePassphrase asks the old passphrase, then the new one twice.
func (h *host) changePassphrase() error {
	title := h.tr("autopanel.title.prompt.passphrase")
	return h.askSecret(title, h.tr("autopanel.label.prompt.passphraseOld"), func(old string) {
		h.busy = false
		_ = h.askSecret(title, h.tr("autopanel.label.prompt.passphraseNew"), func(pw string) {
			h.busy = false
			if auth.Weak(h.me.User, pw) {
				_ = h.p.SetMany(map[string]any{"App.secretError": h.tr("autopanel.notice.account.weak"), "App.secretErrorShown": true})
				return
			}
			h.acct.newPass = pw
			_ = h.askSecret(title, h.tr("autopanel.label.prompt.passphraseAgain"), func(again string) {
				if again != h.acct.newPass {
					h.busy = false
					_ = h.p.SetMany(map[string]any{"App.secretError": h.tr("autopanel.notice.account.mismatch"), "App.secretErrorShown": true})
					return
				}
				h.acct.newPass = ""
				h.background(func(ctx context.Context) error { return h.client.PassphraseChange(ctx, old, again) }, func(err error) {
					h.busy = false
					h.secretAnswered(accountErr(err), func() {
						h.say(h.tr("autopanel.notice.account.passphraseChanged"))
						if h.me.MustChange {
							h.me.MustChange = false
							h.loadPrefs()
							h.startPolling()
							_ = h.panelLeft()
						}
					})
				})
			})
		})
	})
}

// --- two-factor ---------------------------------------------------------------

// openTwoFactor enrols two-factor (the seed shown once, then a code from the
// app, then the recovery codes shown once), or drops it with a code.
func (h *host) openTwoFactor() error {
	if h.me.TOTP {
		return h.prompt("autopanel.title.prompt.totpOff", "autopanel.label.prompt.totpOff", "", func(code string) error {
			h.background(func(ctx context.Context) error { return h.client.TOTPDisable(ctx, strings.TrimSpace(code)) }, func(err error) {
				if err != nil {
					h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
					return
				}
				h.promptDone()
				h.me.TOTP = false
				h.say(h.tr("autopanel.notice.account.totpOff"))
			})
			return nil
		})
	}
	var e auth.Enrol
	h.background(func(ctx context.Context) (err error) { e, err = h.client.TOTPBegin(ctx); return err }, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		text := h.tr("autopanel.label.account.totpSecret") + "\n\n  " + e.Secret + "\n\n" + h.tr("autopanel.label.account.totpURI") + "\n\n  " + e.URI
		_ = h.fill(map[string]any{"App.totpCode": ""})
		_ = h.p.SetMany(map[string]any{"App.totpText": text, "App.totpError": "", "App.totpErrorShown": false})
		_ = h.p.Call("totpDialog", "open")
	})
	return nil
}

// totpConfirmed is the code typed in the enrolment dialog.
func (h *host) totpConfirmed(code string) error {
	var r auth.Recovery
	h.background(func(ctx context.Context) (err error) {
		r, err = h.client.TOTPConfirm(ctx, strings.TrimSpace(code))
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.app.error", err.Error())
			if errors.Is(err, auth.ErrBadCode) {
				msg = h.tr("autopanel.notice.account.badCode")
			}
			_ = h.p.SetMany(map[string]any{"App.totpError": msg, "App.totpErrorShown": true})
			return
		}
		_ = h.p.SetMany(map[string]any{"App.totpText": ""}) // the seed leaves the screen
		_ = h.p.Call("totpDialog", "close")
		h.me.TOTP = true
		h.showOnce(h.tr("autopanel.title.dialog.recovery"), h.tr("autopanel.label.account.recovery")+"\n\n  "+strings.Join(r.Recovery, "\n  "))
	})
	return nil
}

// totpClosed clears the seed from its source when the dialog closes unconfirmed.
func (h *host) totpClosed() error {
	return h.p.SetMany(map[string]any{"App.totpText": ""})
}

// showOnce shows a secret in its dialog; closing it clears it (onceClosed).
func (h *host) showOnce(title, text string) {
	_ = h.p.SetMany(map[string]any{"App.onceTitle": title, "App.onceText": text})
	_ = h.p.Call("onceDialog", "open")
}

func (h *host) onceClosed() error {
	return h.p.SetMany(map[string]any{"App.onceText": ""})
}

// --- API tokens ---------------------------------------------------------------

func (h *host) openTokens() error {
	h.loadTokens()
	return h.openPanel("tokens")
}

func (h *host) loadTokens() {
	var ts []auth.TokenView
	h.background(func(ctx context.Context) (err error) { ts, err = h.client.Tokens(ctx); return err }, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		a := &h.acct
		a.tokenList = ts
		rows := make([]tuidecl.Row, 0, len(ts))
		for _, t := range ts {
			exp := day(t.ExpiresAt)
			if t.Revoked {
				exp = h.tr("autopanel.value.account.revoked")
			}
			rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(t.ID, 10), "id": strconv.FormatInt(t.ID, 10), "name": t.Name, "role": string(t.Role), "owner": t.Owner, "expires": exp})
		}
		a.tokens.Reset(rows)
		_ = h.p.SetMany(map[string]any{
			"App.tokensTitle": h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.tokens"), len(ts), time.Now().Format("15:04:05")),
			"App.tokenDetail": h.tokenDetail(),
		})
	})
}

func (h *host) tokenDetail() string {
	a := &h.acct
	if a.tokenAt < 0 || a.tokenAt >= len(a.tokenList) {
		return h.tr("autopanel.note.account.tokens")
	}
	t := a.tokenList[a.tokenAt]
	return facts(h,
		[2]string{"autopanel.label.account.name", t.Name},
		[2]string{"autopanel.label.account.role", string(t.Role)},
		[2]string{"autopanel.label.account.owner", t.Owner},
		[2]string{"autopanel.label.account.created", day(t.CreatedAt)},
		[2]string{"autopanel.label.account.expires", day(t.ExpiresAt)},
		[2]string{"autopanel.label.account.lastUsed", day(t.LastUsedAt)}) + "\n\n" + h.tr("autopanel.note.account.tokens")
}

func (h *host) tokenMoved(row int) error {
	h.acct.tokenAt = row
	return h.p.Set("App.tokenDetail", h.tokenDetail())
}

// tokenCreate asks a name, a role (viewer unless changed) and the days, then
// shows the token once.
func (h *host) tokenCreate() error {
	return h.prompt("autopanel.title.prompt.tokenName", "autopanel.label.prompt.tokenName", "", func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			h.promptRefused(h.tr("autopanel.notice.account.noName"))
			return nil
		}
		h.promptDone()
		return h.askRole("viewer", func(role auth.Role) {
			_ = h.prompt("autopanel.title.prompt.tokenDays", "autopanel.label.prompt.tokenDays", "90", func(text string) error {
				days, err := strconv.Atoi(strings.TrimSpace(text))
				if err != nil || days < 1 || days > 365 {
					h.promptRefused(h.tr("autopanel.notice.account.badDays"))
					return nil
				}
				var nt auth.NewToken
				h.background(func(ctx context.Context) (err error) {
					nt, err = h.client.TokenCreate(ctx, name, string(role), days)
					return err
				}, func(err error) {
					if err != nil {
						h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
						return
					}
					h.promptDone()
					h.loadTokens()
					h.showOnce(h.tr("autopanel.title.dialog.token"), h.trf("autopanel.label.account.token", name, day(nt.ExpiresAt))+"\n\n  "+nt.Token)
				})
				return nil
			})
		})
	})
}

func (h *host) tokenRevoke(row int) error {
	if row < 0 || row >= len(h.acct.tokenList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return nil
	}
	t := h.acct.tokenList[row]
	return h.ask("autopanel.title.confirm.tokenRevoke", h.trf("autopanel.question.account.revoke", t.Name), func() error {
		h.change(func(ctx context.Context) error { return h.client.TokenRevoke(ctx, t.ID) }, func() {
			h.say(h.trf("autopanel.notice.account.revoked", t.Name))
			h.loadTokens()
		})
		return nil
	})
}
