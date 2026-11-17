package ui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/themes"
	"rsc.io/qr"

	"github.com/yongjohnlee80/autopanel/core/mail"
)

// APP PASSWORDS — Mail › Accounts, the selected account's devices. Each device
// signs in with an app password of its own, which Stalwart makes and the
// dialog shows once: its secret, a QR code of it for a phone, and the settings
// a mail app needs. Done keeps it; anything else (Cancel, Escape, a closed
// panel, a lost connection) leaves it to expire in ten minutes, and Cancel
// revokes it at once.
//
// Decision: docs/decisions/mail.md#mail-apps-sign-in-with-app-passwords

// shownAppPassword is the app password whose dialog is open: what Done keeps
// and Cancel revokes, and its secret for Copy, held only while the dialog is
// open. copied: Copy put the secret on the clipboard, which closing empties.
type shownAppPassword struct {
	address, id, device string
	secret              string
	copied              bool
}

// loadAppPasswords reads the selected account's app passwords.
func (h *host) loadAppPasswords() {
	m := &h.mail
	if m.accountAt < 0 || m.accountAt >= len(m.accountList) {
		m.appsOf, m.appList = "", nil
		h.renderAppPasswords()
		return
	}
	addr := m.accountList[m.accountAt].Address
	var ps []mail.AppPasswordView
	h.background(func(ctx context.Context) (err error) {
		ps, err = h.client.MailAppPasswords(ctx, addr)
		return err
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		if m.accountAt < 0 || m.accountAt >= len(m.accountList) || m.accountList[m.accountAt].Address != addr {
			return // the selection moved on while this was read
		}
		m.appsOf, m.appList = addr, ps
		h.renderAppPasswords()
	})
}

// renderAppPasswords puts the selected account's app passwords on screen.
func (h *host) renderAppPasswords() {
	m := &h.mail
	rows := make([]tuidecl.Row, 0, len(m.appList))
	for _, p := range m.appList {
		state := h.tr("autopanel.value.mail.appKept")
		if p.Pending {
			state = h.trf("autopanel.value.mail.appPending", time.Unix(p.ExpiresAt, 0).Format("15:04"))
		}
		rows = append(rows, tuidecl.Row{"key": p.ID, "device": p.Description,
			"made": time.Unix(p.CreatedAt, 0).Format("2006-01-02"), "state": state})
	}
	m.apps.Reset(rows)
	title := h.tr("autopanel.title.list.mailAppPasswords")
	if m.appsOf != "" {
		title += " · " + m.appsOf
	}
	_ = h.p.SetMany(map[string]any{"App.mailAppPasswordsTitle": title})
}

func (h *host) mailAppPasswordMoved(row int) error {
	h.mail.appAt = row
	return nil
}

// selectedAccount is the address of the account at row, or says there is none.
func (h *host) selectedAccount(row int) (string, bool) {
	if row < 0 || row >= len(h.mail.accountList) {
		h.say(h.tr("autopanel.notice.mail.none"))
		return "", false
	}
	return h.mail.accountList[row].Address, true
}

// mailAddAppPassword asks the device's name, then has the daemon make an app
// password for the account at row, and shows it.
func (h *host) mailAddAppPassword(row int) error {
	addr, ok := h.selectedAccount(row)
	if !ok {
		return nil
	}
	return h.addAppPasswordFor(addr)
}

func (h *host) addAppPasswordFor(addr string) error {
	return h.prompt("autopanel.title.prompt.appPassword", "autopanel.label.prompt.appPassword", "", func(device string) error {
		device = strings.TrimSpace(device)
		if device == "" || len([]rune(device)) > 64 {
			h.promptRefused(h.tr("autopanel.notice.mail.badDevice"))
			return nil
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		var made mail.NewAppPassword
		h.background(func(ctx context.Context) (err error) {
			made, err = h.client.MailAddAppPassword(ctx, addr, device)
			return err
		}, func(err error) {
			h.busy = false
			if err != nil {
				msg := h.trf("autopanel.notice.app.error", err.Error())
				if errors.Is(err, mail.ErrWeakSecret) {
					msg = h.tr("autopanel.notice.mail.weakSecret")
				}
				h.promptRefused(msg)
				return
			}
			h.promptDone()
			h.showAppPassword(addr, device, made)
		})
		return nil
	})
}

// showAppPassword opens the app password's dialog: its secret, once.
func (h *host) showAppPassword(addr, device string, n mail.NewAppPassword) {
	h.appShown = &shownAppPassword{address: addr, id: n.ID, device: device, secret: n.Secret}
	settings := facts(h,
		[2]string{"autopanel.label.mail.appUser", n.User},
		[2]string{"autopanel.label.mail.appIMAP", n.Host + "  " + strconv.Itoa(n.IMAP) + "  SSL/TLS"},
		[2]string{"autopanel.label.mail.appSMTP", n.Host + "  " + strconv.Itoa(n.SMTP) + "  SSL/TLS"},
		[2]string{"autopanel.label.mail.appSMTPAlt", n.Host + "  " + strconv.Itoa(n.Submission) + "  STARTTLS"})
	// The block beside the QR code is short lines only: the dialog shows a
	// text by wrapping it, and a wrapped line would break the code.
	block := "  " + n.Secret + "\n\n  " + groupsOfFour(n.Secret) + "\n\n" + settings
	if code, err := qrText(n.Secret, h.darkTheme()); err == nil {
		block = sideBySide(block, code, 3)
	}
	_ = h.p.SetMany(map[string]any{
		"App.appPwTitle":     h.trf("autopanel.title.dialog.appPassword", addr, device),
		"App.appPwIntro":     h.tr("autopanel.label.mail.appSecret"),
		"App.appPwText":      block,
		"App.appPwNote":      h.trf("autopanel.label.mail.appPending", time.Unix(n.ExpiresAt, 0).Format("15:04")),
		"App.appPwCopyNote":  "",
		"App.appPwCopyShown": false,
	})
	_ = h.p.Call("appPasswordDialog", "open")
}

// appPasswordCopy is Copy password: the secret on the clipboard, through the
// terminal (OSC 52: over SSH, the clipboard of the computer the panel is used
// from), for a mail app there. The dialog says closing it empties the
// clipboard; a terminal that takes no copy is said so.
func (h *host) appPasswordCopy() error {
	shown := h.appShown
	if shown == nil {
		return nil
	}
	note := h.tr("autopanel.notice.mail.appNoClipboard")
	if app := h.p.App(); app != nil && app.CopyToClipboard(shown.secret) {
		shown.copied = true
		note = h.tr("autopanel.notice.mail.appCopied")
	}
	return h.p.SetMany(map[string]any{"App.appPwCopyNote": note, "App.appPwCopyShown": true})
}

// appPasswordDone is Done: the device signed in, so the app password is kept.
func (h *host) appPasswordDone() error {
	shown := h.clearAppPassword()
	if shown == nil {
		return nil
	}
	h.background(func(ctx context.Context) error {
		return h.client.MailKeepAppPassword(ctx, shown.address, shown.id)
	}, func(err error) {
		switch {
		case errors.Is(err, mail.ErrExpired):
			h.say(h.trf("autopanel.notice.mail.appExpired", shown.device))
		case err != nil:
			h.failed(err)
		default:
			h.say(h.trf("autopanel.notice.mail.appKept", shown.device))
		}
		h.loadAppPasswords()
	})
	return nil
}

// appPasswordCancelled is Cancel or Escape: the app password is revoked now,
// rather than left to expire.
func (h *host) appPasswordCancelled() error {
	shown := h.clearAppPassword()
	if shown == nil {
		return nil
	}
	h.background(func(ctx context.Context) error {
		return h.client.MailRevokeAppPassword(ctx, shown.address, shown.id)
	}, func(err error) {
		if err != nil { // it expires on its own: say so, not the failure alone
			h.say(h.trf("autopanel.notice.mail.appNotRevoked", shown.device))
		} else {
			h.say(h.trf("autopanel.notice.mail.appCancelled", shown.device))
		}
		h.loadAppPasswords()
	})
	return nil
}

// clearAppPassword takes the secret off the screen, and off the clipboard if
// Copy put it there, and answers which app password the dialog showed, once.
// The clipboard is emptied without being read first: a terminal asked to read
// it may ask the user or refuse, and the dialog said closing empties it.
func (h *host) clearAppPassword() *shownAppPassword {
	shown := h.appShown
	h.appShown = nil
	if shown != nil {
		if shown.copied {
			if app := h.p.App(); app != nil {
				app.CopyToClipboard("")
			}
		}
		shown.secret = ""
	}
	_ = h.p.SetMany(map[string]any{"App.appPwText": "", "App.appPwIntro": "", "App.appPwTitle": "", "App.appPwNote": "",
		"App.appPwCopyNote": "", "App.appPwCopyShown": false})
	return shown
}

// mailRevokeAppPassword revokes the selected app password, after a
// confirmation naming its device.
func (h *host) mailRevokeAppPassword(row int) error {
	m := &h.mail
	if row < 0 || row >= len(m.appList) || m.appsOf == "" {
		h.say(h.tr("autopanel.notice.mail.noAppPassword"))
		return nil
	}
	addr, p := m.appsOf, m.appList[row]
	return h.ask("autopanel.title.confirm.appRevoke", h.trf("autopanel.question.mail.appRevoke", p.Description, addr), func() error {
		h.change(func(ctx context.Context) error { return h.client.MailRevokeAppPassword(ctx, addr, p.ID) }, func() {
			h.say(h.trf("autopanel.notice.mail.appRevoked", p.Description))
			h.loadAppPasswords()
		})
		return nil
	})
}

// mailLockAccount replaces a typed password with one no one knows, after a
// confirmation that says the devices using it stop.
func (h *host) mailLockAccount(row int) error {
	addr, ok := h.selectedAccount(row)
	if !ok {
		return nil
	}
	return h.ask("autopanel.title.confirm.mailLock", h.trf("autopanel.question.mail.lock", addr), func() error {
		h.change(func(ctx context.Context) error { return h.client.MailLockAccount(ctx, addr) }, func() {
			h.say(h.trf("autopanel.notice.mail.locked", addr))
		})
		return nil
	})
}

// sideBySide sets right's lines beside left's, gap cells apart, left's
// padded to its widest line: one block of text, which a dialog shows as it is.
func sideBySide(left, right string, gap int) string {
	l, r := strings.Split(left, "\n"), strings.Split(right, "\n")
	width := 0
	for _, line := range l {
		width = max(width, tui.StringWidth(line))
	}
	var b strings.Builder
	for i := range max(len(l), len(r)) {
		a, c := "", ""
		if i < len(l) {
			a = l[i]
		}
		if i < len(r) {
			c = r[i]
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(a)
		if c != "" {
			b.WriteString(strings.Repeat(" ", width-tui.StringWidth(a)+gap) + c)
		}
	}
	return b.String()
}

// groupsOfFour is a secret in groups of four characters, for reading it out
// or checking it; the mail app takes it without the spaces.
func groupsOfFour(s string) string {
	var b strings.Builder
	for i, r := range []rune(s) {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// darkTheme reports whether the theme on screen draws on a dark window.
func (h *host) darkTheme() bool {
	vals, err := themes.Values(h.theme)
	if err != nil {
		return true
	}
	return luminance(vals["app.window"]) < 0.5
}

// luminance is a #rrggbb colour's relative lightness, 0 to 1; 0 for anything
// else.
func luminance(hex string) float64 {
	if len(hex) != 7 || hex[0] != '#' {
		return 0
	}
	v, err := strconv.ParseUint(hex[1:], 16, 32)
	if err != nil {
		return 0
	}
	r, g, b := float64(v>>16&0xff)/255, float64(v>>8&0xff)/255, float64(v&0xff)/255
	return 0.2126*r + 0.7152*g + 0.0722*b
}

// qrQuiet is the margin of light modules around the code. The standard asks
// four; scanners read two, and the dialog is short of rows.
const qrQuiet = 2

// qrText draws text's QR code in half blocks: two module rows per line. The
// text's colour draws one kind of module and the window the other, so on a
// dark window the blocks are the light modules, and on a light one the dark:
// either way the code reads dark on light, as cameras expect.
func qrText(text string, dark bool) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := c.Size + 2*qrQuiet
	on := func(x, y int) bool {
		x, y = x-qrQuiet, y-qrQuiet
		black := x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Black(x, y)
		return black != dark // dark window: draw the light modules
	}
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			top, bottom := on(x, y), y+1 < n && on(x, y+1) // past the last row: the window's own colour
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		if y+2 < n {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
