package ui

import (
	"context"

	"github.com/yongjohnlee80/golib/tui"
)

// SIGN-IN — the login dialog. The panel opens signed out and reads nothing
// until a panel user has logged in: the dialog is the first thing on screen.
//
// A dialog closes when it is answered, as Qt's does. A refused answer (no
// user, or the service saying no) opens it again, the reason on its help
// line. One attempt runs at a time. Cancelling quits: a signed-out panel has
// nothing to show, and every verb but the login is refused.
//
// The passphrase is passed to the Client and kept nowhere here: no source
// holds it, and the field is emptied each time the dialog opens.

// defaultUser is the name the login starts with: the user --init makes.
const defaultUser = "root"

// promptLogin opens the login dialog. Posted: at the start the program's
// loop is not running yet, and after a refusal the handler that refused is
// still closing the dialog.
func (h *host) promptLogin() {
	h.p.Post(func() { _ = h.p.Call("loginDialog", "open") })
}

// refuseLogin opens the login again, saying why.
func (h *host) refuseLogin(why string) {
	_ = h.p.Set("App.loginError", why)
	h.promptLogin()
}

// login is App.login: the login dialog answered.
func (h *host) login(user, pass string) error {
	if user == "" {
		user = defaultUser
	}
	_ = h.p.Set("App.lastUser", user)
	if h.signingIn {
		h.refuseLogin(h.tr("autopanel.login.running"))
		return nil
	}
	h.signingIn = true
	h.background(func(ctx context.Context) error { return h.client.Login(ctx, user, pass) }, func(err error) {
		h.signingIn = false
		if err != nil {
			h.refuseLogin(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		h.signedIn = true
		_ = h.p.SetMany(map[string]any{"App.loginError": "", "App.status": tui.Msg("autopanel.status.loading")})
		h.say(h.trf("autopanel.login.signedIn", user))
		h.refresh()
		h.loadPrefs()
	})
	return nil
}

// loginDeclined is App.loginDeclined: the login cancelled. The panel quits.
func (h *host) loginDeclined() error {
	h.p.Quit()
	return nil
}
