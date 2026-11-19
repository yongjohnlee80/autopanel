package ui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/tunnel"
)

// Routes › Tunnels: the agents on the left, the selected one on the right.
// An agent is a machine with no open port that dials this server and holds a
// tunnel open; a route or a forward reaches a service on it as
// tunnel://<agent>/<target>. Add asks for a name and shows the enrolment
// token once. Remove asks first.
//
// Decision: docs/decisions/forwards.md#tunnels

// tunnelsState is the tunnels panel's state.
type tunnelsState struct {
	model *tuidecl.ListModel // App.tunnels
	list  []tunnel.View
	read  bool
	err   error
	at    int
}

func newTunnelsState() tunnelsState {
	return tunnelsState{model: tuidecl.NewListModel("key", "name", "state", "targets")}
}

// openTunnels is Routes › Tunnels.
func (h *host) openTunnels() error {
	h.loadTunnels()
	return h.openPanel("tunnels")
}

// tunnelWord is an agent's state in one word, for the list.
func (h *host) tunnelWord(v tunnel.View) string {
	switch {
	case v.State != "enrolled":
		return h.tr("autopanel.value.tunnels." + v.State) // waiting, expired
	case v.Connected:
		return h.tr("autopanel.value.tunnels.up")
	}
	return h.tr("autopanel.value.tunnels.down")
}

// loadTunnels reads the agents, off the loop.
func (h *host) loadTunnels() {
	var list []tunnel.View
	h.background(func(ctx context.Context) error {
		var err error
		list, err = h.client.Agents(ctx)
		return err
	}, func(err error) {
		t := &h.tun
		t.err = err
		if err == nil {
			t.list, t.read = list, true
			rows := make([]tuidecl.Row, 0, len(list))
			for _, v := range list {
				rows = append(rows, tuidecl.Row{"key": v.Name, "name": v.Name, "state": h.tunnelWord(v), "targets": strconv.Itoa(len(v.Targets))})
			}
			t.model.Reset(rows)
		}
		h.renderTunnels()
	})
}

// renderTunnels puts the tunnels panel's title and details on screen.
func (h *host) renderTunnels() {
	t := &h.tun
	title := h.tr("autopanel.title.list.tunnels")
	if t.err != nil {
		title = h.trf("autopanel.title.list.failed", title, t.err.Error())
	} else if t.read {
		title = h.trf("autopanel.title.list.count", title, len(t.list), time.Now().Format("15:04:05"))
	}
	_ = h.p.SetMany(map[string]any{"App.tunnelsTitle": title, "App.tunnelDetail": h.tunnelDetailAt(t.at)})
}

func minute(t int64) string { return time.Unix(t, 0).Format("2006-01-02 15:04") }

func (h *host) tunnelDetailAt(row int) string {
	t := &h.tun
	if row < 0 || row >= len(t.list) {
		return h.tr("autopanel.label.tunnels.empty")
	}
	v := t.list[row]
	switch v.State {
	case "waiting":
		return v.Name + "\n\n" + h.trf("autopanel.label.tunnels.waiting", minute(v.TokenExpires))
	case "expired":
		return v.Name + "\n\n" + h.tr("autopanel.label.tunnels.expired")
	}
	line := h.tr("autopanel.value.tunnels.down")
	if v.Connected {
		line = h.trf("autopanel.value.tunnels.since", minute(v.Since), v.From, v.Streams)
	}
	targets := h.tr("autopanel.value.tunnels.noTargets")
	if len(v.Targets) > 0 {
		targets = strings.Join(v.Targets, ", ")
	}
	return v.Name + "\n\n" + facts(h,
		[2]string{"autopanel.label.tunnels.tunnel", line},
		[2]string{"autopanel.label.tunnels.targets", targets},
		[2]string{"autopanel.label.tunnels.address", "tunnel://" + v.Name + "/<target>"},
		[2]string{"autopanel.label.tunnels.fingerprint", v.Fingerprint},
		[2]string{"autopanel.label.tunnels.enrolled", h.trf("autopanel.value.tunnels.enrolledFrom", minute(v.EnrolledAt), v.EnrolledFrom)}) +
		"\n\n" + h.tr("autopanel.label.tunnels.compare")
}

// tunnelMoved is the agents list's cursor moved.
func (h *host) tunnelMoved(row int) error {
	h.tun.at = row
	return h.p.Set("App.tunnelDetail", h.tunnelDetailAt(row))
}

// addTunnel is Add in the tunnels panel: a name is asked, the agent is added,
// and its enrolment token is shown once with what to run on its machine.
func (h *host) addTunnel() error {
	return h.prompt("autopanel.title.prompt.tunnel", "autopanel.label.prompt.tunnel", "", func(text string) error {
		name := strings.TrimSpace(text)
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		var added tunnel.Added
		h.background(func(ctx context.Context) error {
			var err error
			added, err = h.client.AddAgent(ctx, name)
			return err
		}, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, tunnel.ErrBadName):
				h.promptRefused(h.tr("autopanel.notice.tunnels.name"))
			case err != nil:
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
			default:
				h.promptDone()
				h.showOnce(h.tr("autopanel.title.dialog.tunnelToken"),
					h.trf("autopanel.label.tunnels.token", added.Agent.Name, minute(added.Expires))+"\n\n  "+added.Token)
				h.loadTunnels()
			}
		})
		return nil
	})
}

// removeTunnel asks before removing the agent at row.
func (h *host) removeTunnel(row int) error {
	t := &h.tun
	if row < 0 || row >= len(t.list) {
		h.say(h.tr("autopanel.notice.tunnels.none"))
		return nil
	}
	v := t.list[row]
	return h.ask("autopanel.title.confirm.removeTunnel", h.trf("autopanel.question.tunnels.remove", v.Name), func() error {
		if h.busy {
			h.say(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error { return h.client.RemoveAgent(ctx, v.ID) }, func(err error) {
			h.busy = false
			if err != nil {
				h.failed(err)
			} else {
				h.say(h.trf("autopanel.notice.tunnels.removed", v.Name))
			}
			h.loadTunnels()
		})
		return nil
	})
}
