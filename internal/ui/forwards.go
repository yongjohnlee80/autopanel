package ui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/forward"
)

// Routes › Port forwarding: the forwards on the left, the selected one on the
// right. Add asks for one line (a name, the public port or range, the target,
// then any sources), shows what the daemon's review says of the firewall, and
// adds it as reviewed. Remove asks first.
//
// Decision: docs/decisions/forwards.md

// forwardsState is the forwards panel's state.
type forwardsState struct {
	model *tuidecl.ListModel // App.forwards
	list  []forward.View
	read  bool
	err   error
	at    int
}

func newForwardsState() forwardsState {
	return forwardsState{model: tuidecl.NewListModel("key", "name", "ports", "target")}
}

// forwardPorts is a forward's public ports: "25565", or "6000-6009".
func forwardPorts(from, to int) string {
	if to > from {
		return strconv.Itoa(from) + "-" + strconv.Itoa(to)
	}
	return strconv.Itoa(from)
}

// openForwards is Routes › Port forwarding.
func (h *host) openForwards() error {
	h.loadForwards()
	return h.openPanel("forwards")
}

// loadForwards reads the forwards, off the loop.
func (h *host) loadForwards() {
	var list []forward.View
	h.background(func(ctx context.Context) error {
		var err error
		list, err = h.client.Forwards(ctx)
		return err
	}, func(err error) {
		f := &h.fwd
		f.err = err
		if err == nil {
			f.list, f.read = list, true
			rows := make([]tuidecl.Row, 0, len(list))
			for _, v := range list {
				rows = append(rows, tuidecl.Row{"key": v.Name, "name": v.Name, "ports": v.Proto + "/" + forwardPorts(v.From, v.To), "target": v.Target})
			}
			f.model.Reset(rows)
		}
		h.renderForwards()
	})
}

// renderForwards puts the forwards panel's title and details on screen.
func (h *host) renderForwards() {
	f := &h.fwd
	title := h.tr("autopanel.title.list.forwards")
	if f.err != nil {
		title = h.trf("autopanel.title.list.failed", title, f.err.Error())
	} else if f.read {
		title = h.trf("autopanel.title.list.count", title, len(f.list), time.Now().Format("15:04:05"))
	}
	_ = h.p.SetMany(map[string]any{"App.forwardsTitle": title, "App.forwardDetail": h.forwardDetailAt(f.at)})
}

func (h *host) forwardDetailAt(row int) string {
	f := &h.fwd
	if row < 0 || row >= len(f.list) {
		return ""
	}
	v := f.list[row]
	header, sources := h.tr("autopanel.value.forwards.notSent"), h.tr("autopanel.value.forwards.any")
	if v.Proxy {
		header = h.tr("autopanel.value.forwards.sent")
	}
	if len(v.Allow) > 0 {
		sources = strings.Join(v.Allow, ", ")
	}
	return v.Name + "\n\n" + facts(h,
		[2]string{"autopanel.label.forwards.public", v.Proto + "/" + forwardPorts(v.From, v.To)},
		[2]string{"autopanel.label.forwards.target", v.Target},
		[2]string{"autopanel.label.forwards.header", header},
		[2]string{"autopanel.label.forwards.sources", sources})
}

// forwardMoved is the forwards list's cursor moved.
func (h *host) forwardMoved(row int) error {
	h.fwd.at = row
	return h.p.Set("App.forwardDetail", h.forwardDetailAt(row))
}

// forwardSpec reads the one line of the form: a name, the public port or a
// range (6000-6009; "udp/5353" for UDP), the target, then any sources.
func forwardSpec(text string) (forward.Spec, bool) {
	words := strings.Fields(text)
	if len(words) < 3 {
		return forward.Spec{}, false
	}
	s := forward.Spec{Name: words[0], Target: words[2], Allow: words[3:]}
	port := words[1]
	if rest, ok := strings.CutPrefix(port, "udp/"); ok { // "udp/5353": a UDP forward
		s.Proto, port = "udp", rest
	} else {
		port = strings.TrimPrefix(port, "tcp/")
	}
	from, to, isRange := strings.Cut(port, "-")
	var err error
	if s.From, err = strconv.Atoi(from); err != nil {
		return forward.Spec{}, false
	}
	if isRange {
		if s.To, err = strconv.Atoi(to); err != nil || s.To <= 0 {
			return forward.Spec{}, false // "25565-0" is no range: 0 would read as "one port"
		}
	}
	return s, true
}

// addForward is Add in the forwards panel: the line is asked, reviewed by the
// daemon, and what the review says is confirmed before anything changes.
func (h *host) addForward() error {
	return h.prompt("autopanel.title.prompt.forward", "autopanel.label.prompt.forward", "", func(text string) error {
		spec, ok := forwardSpec(text)
		if !ok {
			h.promptRefused(h.tr("autopanel.notice.forwards.shape"))
			return nil
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		var r forward.Review
		h.background(func(ctx context.Context) error {
			var err error
			r, err = h.client.CheckForward(ctx, spec)
			return err
		}, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, forward.ErrSSH):
				h.promptRefused(h.tr("autopanel.notice.forwards.ssh"))
			case errors.Is(err, forward.ErrBadTarget):
				h.promptRefused(h.tr("autopanel.notice.forwards.target"))
			case err != nil:
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
			default:
				h.promptDone()
				_ = h.confirmForward(spec, r)
			}
		})
		return nil
	})
}

// confirmForward shows what a forward would be and what adding it does to the
// firewall, and adds it on Yes: with its port opened when the firewall blocks
// it and AutoPanel can open it.
func (h *host) confirmForward(spec forward.Spec, r forward.Review) error {
	v := r.Forward
	ports := v.Proto + "/" + forwardPorts(v.From, v.To)
	question := h.trf("autopanel.question.forwards.add", v.Name, ports, v.Target)
	open := false
	for _, p := range r.Ports {
		switch {
		case p.Needs && p.Managed:
			open = true
			question += "\n\n" + h.trf("autopanel.question.forwards.open", ports)
		case p.Needs:
			question += "\n\n" + h.trf("autopanel.question.forwards.manual", ports)
			if len(p.Commands) > 0 {
				question += "\n\n  " + strings.Join(p.Commands, "\n  ")
			}
		}
	}
	return h.ask("autopanel.title.confirm.addForward", question, func() error {
		if h.busy {
			h.say(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error {
			_, err := h.client.AddForward(ctx, forward.Apply{Spec: spec, Accept: r.SHA256, Open: open})
			return err
		}, func(err error) {
			h.busy = false
			if err != nil {
				h.failed(err)
			} else {
				h.say(h.trf("autopanel.notice.forwards.added", ports, v.Target))
			}
			h.loadForwards()
		})
		return nil
	})
}

// removeForward asks before removing the forward at row.
func (h *host) removeForward(row int) error {
	f := &h.fwd
	if row < 0 || row >= len(f.list) {
		h.say(h.tr("autopanel.notice.forwards.none"))
		return nil
	}
	v := f.list[row]
	return h.ask("autopanel.title.confirm.removeForward", h.trf("autopanel.question.forwards.remove", v.Name), func() error {
		if h.busy {
			h.say(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error { return h.client.RemoveForward(ctx, v.ID) }, func(err error) {
			h.busy = false
			if err != nil {
				h.failed(err)
			} else {
				h.say(h.trf("autopanel.notice.forwards.removed", v.Name))
			}
			h.loadForwards()
		})
		return nil
	})
}
