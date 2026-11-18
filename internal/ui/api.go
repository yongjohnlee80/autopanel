package ui

import (
	"context"
	"errors"
	"strings"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// The HTTPS API's host, from the System menu: one line, the host and then any
// source ranges that may call it; an empty line turns the API off. Only an
// admin may change it; the daemon refuses anyone else.
//
// Decision: docs/decisions/api.md

// API is the HTTPS API's settings: its host ("" while it is off) and the
// source prefixes that may call it (none: any address).
type API struct {
	Host  string
	Allow []string
}

// setAPI is System → HTTPS API…: the settings in use are read first, so the
// field opens on them.
func (h *host) setAPI() error {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return nil
	}
	var cur API
	h.background(func(ctx context.Context) error {
		var err error
		cur, err = h.client.APISettings(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.app.error", err.Error()))
			return
		}
		_ = h.prompt("autopanel.title.prompt.api", "autopanel.label.prompt.api", strings.Join(append([]string{cur.Host}, cur.Allow...), " "), h.apiAnswered)
	})
	return nil
}

// apiAnswered is OK in the API's prompt: the first word is the host, the rest
// are source ranges.
func (h *host) apiAnswered(text string) error {
	words := strings.Fields(text)
	var ask API
	if len(words) > 0 {
		ask = API{Host: words[0], Allow: words[1:]}
	}
	if h.busy {
		h.promptRefused(h.tr("autopanel.notice.app.busy"))
		return nil
	}
	h.busy = true
	var now API
	h.background(func(ctx context.Context) error {
		var err error
		now, err = h.client.SetAPI(ctx, ask)
		return err
	}, func(err error) {
		h.busy = false
		switch {
		case errors.Is(err, gate.ErrNoDomain):
			h.promptRefused(h.trf("autopanel.notice.api.noDomain", ask.Host))
		case errors.Is(err, gate.ErrBadHost):
			h.promptRefused(h.trf("autopanel.notice.domains.badName", ask.Host))
		case err != nil:
			h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
		case now.Host == "":
			h.promptDone()
			h.say(h.tr("autopanel.notice.api.off"))
		default:
			h.promptDone()
			h.say(h.trf("autopanel.notice.api.set", now.Host))
			h.refresh() // its certificate is now one of the list's
		}
	})
	return nil
}
