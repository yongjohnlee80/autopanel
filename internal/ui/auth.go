package ui

import (
	"context"

	"github.com/yongjohnlee80/golib/tui"
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
// still closing the dialog.
func (h *host) promptLogin() {
	h.p.Post(func() { _ = h.p.Call("loginDialog", "open") })
}

// refuseLogin opens the login again, saying why.
func (h *host) refuseLogin(why string) {
	_ = h.p.SetMany(map[string]any{"App.loginError": why, "App.loginErrorShown": true})
	h.promptLogin()
}

// login is App.login: the login dialog answered, by its button or by Enter in
// the passphrase. The dialog is closed while the daemon is asked: a close by
// the host answers nothing, so it never reads as Quit.
func (h *host) login(user, pass string) error {
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
	h.background(func(ctx context.Context) error { return h.client.Login(ctx, user, pass) }, func(err error) {
		h.signingIn = false
		if err != nil {
			h.refuseLogin(h.trf("autopanel.notice.app.error", err.Error()))
			return
		}
		h.signedIn = true
		_ = h.p.SetMany(map[string]any{"App.loginError": "", "App.loginErrorShown": false, "App.status": tui.Msg("autopanel.status.bar.loading")})
		h.say(h.trf("autopanel.notice.login.signedIn", user))
		h.loadPrefs()
		h.startPolling()
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
