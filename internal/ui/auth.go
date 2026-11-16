package ui

import (
	"context"
	"errors"
	"time"

	"github.com/yongjohnlee80/golib/tui"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// SIGN-IN — the login dialog. The panel opens signed out and reads nothing
// until a panel user has logged in: the dialog is the first thing on screen.
//
// An answer closes the dialog while the daemon is asked; a refused answer (no
// user, or the service saying no) opens it again, the reason in its error
// line. One attempt runs at a time. Quitting it quits: a signed-out panel has
// nothing to show, and every verb but the login is refused.
//
// The passphrase is passed to the Client and kept nowhere here: no source
// holds it, and the field is emptied each time the dialog opens.

// defaultUser is the name the login starts with: the user --init makes.
const defaultUser = "root"

// promptLogin opens the login dialog. Posted: at the start the program's
// loop is not running yet, and after a refusal the handler that refused is
// still closing the dialog. Before it opens it asks whether the vault is
// locked, so the dialog can say so before anyone types (N3).
func (h *host) promptLogin() {
	h.p.Post(func() {
		var locked bool
		h.background(func(ctx context.Context) error {
			var err error
			locked, err = h.client.VaultLocked(ctx)
			return err
		}, func(err error) {
			_ = h.p.Set("App.loginVaultLocked", err == nil && locked)
			_ = h.p.Call("loginDialog", "open")
		})
	})
}

// refuseLogin opens the login again, saying why.
func (h *host) refuseLogin(why string) {
	_ = h.p.SetMany(map[string]any{"App.loginError": why, "App.loginErrorShown": true})
	h.promptLogin()
}

// login is App.login: the login dialog answered, by its button or by Enter in
// the code field. The dialog is closed while the daemon is asked: a close by
// the host answers nothing, so it never reads as Quit.
func (h *host) login(user, pass, code string) error {
	_ = h.p.Call("loginDialog", "close")
	if user == "" {
		user = defaultUser
	}
	_ = h.p.Set("App.lastUser", user)
	if h.signingIn {
		h.refuseLogin(h.tr("autopanel.notice.login.running"))
		return nil
	}
	h.signingIn = true
	var me auth.Whoami
	h.background(func(ctx context.Context) error {
		if _, err := h.client.Login(ctx, user, pass, code); err != nil {
			return err
		}
		var err error
		me, err = h.client.Whoami(ctx)
		return err
	}, func(err error) {
		h.signingIn = false
		if err != nil {
			h.refuseLogin(h.trf("autopanel.notice.app.error", err.Error()))
			return
		}
		h.signedIn = true
		h.setMe(me)
		h.touch()
		if me.MustChange { // nothing else is allowed until it is done (M2)
			_ = h.changePassphrase()
			_ = h.p.SetMany(map[string]any{"App.secretError": h.tr("autopanel.notice.account.mustChange"), "App.secretErrorShown": true})
			return
		}
		_ = h.p.SetMany(map[string]any{"App.loginError": "", "App.loginErrorShown": false, "App.status": tui.Msg("autopanel.status.bar.loading")})
		h.say(h.trf("autopanel.notice.login.signedIn", user))
		h.loadPrefs()
		h.startPolling()
		h.loadMail() // the Mail menu's state, for Set up mail
		_ = h.panelLeft()
	})
	return nil
}

// loginDeclined is App.loginDeclined: the login's Quit, or Escape. The panel
// quits.
func (h *host) loginDeclined() error {
	h.p.Quit()
	return nil
}

// setMe puts who is logged in on screen: the menus a role cannot use are
// greyed out (the daemon refuses regardless).
func (h *host) setMe(me auth.Whoami) {
	h.me = me
	admin := me.Role == auth.RoleAdmin
	changes := admin || me.Role == auth.RoleOperator
	_ = h.p.SetMany(map[string]any{
		"App.isAdmin":    admin,
		"App.canChange":  changes,
		"App.canMail":    changes || me.Role == auth.RoleMail,
		"App.canReadAll": changes || me.Role == auth.RoleViewer,
	})
	h.renderCloudflare()
}

// idleAfter is how long the panel waits with no key from its person before
// it asks for the login again (D6). A variable so a test need not wait.
var idleAfter = 30 * time.Minute

// touch records a person's action: every command the screen sends is one; the
// panel's own five-second reads are not.
func (h *host) touch() { h.lastAction = time.Now() }

// checkIdle signs the panel out after idleAfter with no action, and when the
// daemon says the session has ended (12 hours at most).
func (h *host) checkIdle() {
	if h.signedIn && !h.lastAction.IsZero() && time.Since(h.lastAction) > idleAfter {
		h.signOut(h.tr("autopanel.notice.login.idle"))
	}
}

// signOut stops reading and asks for the login again; the next login
// replaces this connection's.
func (h *host) signOut(why string) {
	h.signedIn = false
	// a secret shown once leaves the screen with its person
	_ = h.p.Call("totpDialog", "close")
	_ = h.p.Call("onceDialog", "close")
	_ = h.p.SetMany(map[string]any{"App.loginError": why, "App.loginErrorShown": true, "App.totpText": "", "App.onceText": ""})
	h.promptLogin()
}

// expired reports a daemon's answer that the login has ended.
func expired(err error) bool { return errors.Is(err, auth.ErrExpired) }
