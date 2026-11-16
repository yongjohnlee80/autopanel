package ui

import (
	"context"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// The Cloudflare token, from the Certs menu: typed unseen into the password
// dialog, checked by the daemon with Cloudflare before it is sealed, or
// forgotten. Only an admin may do either; the daemon refuses anyone else.

// setCloudflare is Certs → Cloudflare token…: the token, typed unseen. A token
// Cloudflare refuses keeps the dialog open, with the reason under the field.
func (h *host) setCloudflare() error {
	err := h.askSecret(h.tr("autopanel.title.prompt.cloudflare"), h.tr("autopanel.label.prompt.cloudflare"), func(tok string) {
		h.background(func(ctx context.Context) error { return h.client.SetCloudflare(ctx, strings.TrimSpace(tok)) }, func(err error) {
			h.busy = false
			h.secretAnswered(err, func() {
				h.say(h.tr("autopanel.notice.certs.cloudflareSet"))
				h.refresh()
			})
		})
	})
	h.secretShort = "autopanel.notice.certs.cloudflareShort"
	return err
}

// clearCloudflare is Certs → Remove Cloudflare token…, after a confirmation.
func (h *host) clearCloudflare() error {
	return h.ask("autopanel.title.confirm.cloudflareClear", h.tr("autopanel.question.certs.cloudflareClear"), func() error {
		h.change(func(ctx context.Context) error { return h.client.ClearCloudflare(ctx) }, func() {
			h.say(h.tr("autopanel.notice.certs.cloudflareCleared"))
			h.refresh()
		})
		return nil
	})
}

// renderCloudflare enables Remove Cloudflare token… for an admin while a token
// is in use: the menu's bindings cannot join two sources.
func (h *host) renderCloudflare() {
	_ = h.p.SetMany(map[string]any{"App.cloudflareClearable": h.cloudflareClearable()})
}

// cloudflareClearable says whether an admin is logged in while a token is in
// use.
func (h *host) cloudflareClearable() bool {
	dns := h.status != nil && strings.HasPrefix(h.status.Challenge, "dns-01")
	return dns && h.me.Role == auth.RoleAdmin
}
