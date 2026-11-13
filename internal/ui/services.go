package ui

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// THE SERVICES MENU — the stacks in a floating panel, a row per container,
// and what is done to one: added from its definition folder, applied, its
// images pulled, started, stopped, restarted, removed, its log read. A stack
// is added or applied only after its review: what it would run, and what the
// policy refuses or warns of. Every one is a verb of the daemon's, which
// records the ones that change the host before it runs them. The panel reads
// the list again after each, and r in the panel reads it again.

// The reviews the panel shows, by what confirming one does.
const (
	reviewAdd   = "add"   // a new stack: services.add, or services.prepare
	reviewApply = "apply" // a registered stack: services.apply
	reviewStart = "start" // a prepared stack: services.add starts it
)

// changedMark follows the name of a stack whose definition changed since it
// was applied.
const changedMark = "*"

// stackRow is what a row of the table names: a stack, and one service of it,
// or "" on the row of a stack that has no container yet.
type stackRow struct {
	stack   int // the stack's place in stacks.views
	service string
}

// stacks is the Services panels' models and what they were last filled from.
type stacks struct {
	model     *tuidecl.ListModel // App.stacks: the table's rows
	logs      *tuidecl.ListModel // App.stackLogs: journal lines
	available *tuidecl.ListModel // App.available: the folders to add a stack from
	planned   *tuidecl.ListModel // App.reviewContainers: what a review would run
	findings  *tuidecl.ListModel // App.reviewFindings: what a review says

	shown  bool            // the stacks panel is open, minimized or not
	views  []services.View // the stacks, as the daemon gave them
	rows   []stackRow      // the table's rows, by row
	read   bool            // the stacks have been read once
	readAt time.Time

	folders []services.Folder // the add dialog's rows

	logsOf      string // the stack the log panel shows
	logsService string // and the service of it, or "" for all
	logLines    int
	logsAt      time.Time

	reviewName   string          // the stack the review is of
	reviewMode   string          // reviewAdd, reviewApply or reviewStart
	review       services.Review // the review on screen
	findingTexts []string        // the review's findings, whole, by row

	askName    string // the stack the confirmation names
	askService string // and the service of it, for a stop
	askPurge   bool   // whether a removal deletes the directory too
}

func newStacks() stacks {
	return stacks{
		model:     tuidecl.NewListModel("key", "stack", "service", "state", "health", "memory", "restarts", "ports", "image"),
		logs:      tuidecl.NewListModel("key", "line"),
		available: tuidecl.NewListModel("key", "name"),
		planned:   tuidecl.NewListModel("key", "service", "image", "user", "network", "ports", "mounts", "memory"),
		findings:  tuidecl.NewListModel("key", "level", "text"),
	}
}

// state is the Services panels' part of the App singleton's state.
func (d *stacks) state() map[string]any {
	return map[string]any{
		"App.stacks":           d.model,
		"App.stackLogs":        d.logs,
		"App.available":        d.available,
		"App.reviewContainers": d.planned,
		"App.reviewFindings":   d.findings,
		"App.stacksNote":       "",
		"App.stackLogsNote":    "",
		"App.availableAny":     false,
		"App.availableNote":    "",
		"App.reviewTitle":      "",
		"App.reviewSummary":    "",
		"App.reviewRemoves":    "",
		"App.reviewRemovesAny": false,
		"App.reviewFinding":    "",
		"App.reviewHelp":       "",
		"App.reviewGo":         englishText("autopanel.review.go.apply"),
		"App.reviewAllowed":    false,
		"App.reviewNew":        false,
		"App.reviewMayPrepare": false,
	}
}

// portsText is a container's ports on one line: "tcp 8080, udp 49152-49999".
func portsText(ports []services.PortUse) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		s := p.Proto + " " + strconv.Itoa(p.From)
		if p.To != p.From {
			s += "-" + strconv.Itoa(p.To)
		}
		parts = append(parts, s)
	}
	return listText(parts)
}

// listText is parts on one line, or "-" for none.
func listText(parts []string) string {
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// shortImage is an image's reference as the table shows it: without Docker
// Hub's prefix, which every unqualified name has, with its tag kept, and with
// a digest cut to its first 12 digits.
func shortImage(image string) string {
	image = strings.TrimPrefix(image, "docker.io/")
	image = strings.TrimPrefix(image, "library/")
	const algo = "@sha256:"
	if i := strings.Index(image, algo); i >= 0 && len(image) > i+len(algo)+12 {
		image = image[:i+len(algo)+12]
	}
	return orDash(image)
}

// shortSHA is the first 12 digits of a hash: enough to tell two reviews apart.
func shortSHA(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return orDash(sum)
}

// unitState is a container's unit as systemd names it, "active (running)".
func unitState(c services.Container) string {
	switch {
	case c.Active == "":
		return "-"
	case c.Sub == "" || c.Sub == c.Active:
		return c.Active
	}
	return c.Active + " (" + c.Sub + ")"
}

// stackState is where a stack is, in words, when that is not "deployed"; ""
// when it is.
func stackState(w wording, v services.View) string {
	switch v.State {
	case string(services.Deployed), "":
		return ""
	case services.Incomplete:
		return w.trf("autopanel.stacks.state.incomplete", orDash(v.Step))
	case string(services.Deploying), string(services.Removing), services.Prepared, services.LegacyRow:
		return w.tr("autopanel.stacks.state." + v.State)
	}
	return v.State
}

// containerState is a container's state in the table. One a person stopped
// is "stopped", whatever systemd says of its unit: systemd may call it
// failed. A stack that is not simply deployed says so first.
func containerState(w wording, v services.View, c services.Container) string {
	state := unitState(c)
	if c.Stopped {
		state = w.tr("autopanel.stacks.state.stopped")
	}
	if of := stackState(w, v); of != "" {
		return of + " · " + state
	}
	return state
}

// stackName is a stack's name in the table, marked when its definition
// changed since it was applied.
func stackName(v services.View) string {
	if v.Changed {
		return v.Name + changedMark
	}
	return v.Name
}

// stackRows are the table's rows: one per container, or one for a stack that
// has none yet, with its state in words. names says which stack and service
// each row is.
func stackRows(w wording, views []services.View) (rows []tuidecl.Row, names []stackRow) {
	for i, v := range views {
		if len(v.Containers) == 0 {
			state := stackState(w, v)
			if state == "" {
				state = v.State
			}
			rows = append(rows, tuidecl.Row{"key": v.Name + "/", "stack": stackName(v), "service": "-", "state": state,
				"health": "-", "memory": "-", "restarts": "-", "ports": "-", "image": "-"})
			names = append(names, stackRow{stack: i})
			continue
		}
		for _, c := range v.Containers {
			memory := "-"
			if c.MemoryBytes > 0 {
				memory = bytesText(c.MemoryBytes)
			}
			rows = append(rows, tuidecl.Row{"key": v.Name + "/" + c.Service, "stack": stackName(v), "service": c.Service,
				"state": containerState(w, v, c), "health": orDash(c.Health), "memory": memory,
				"restarts": strconv.Itoa(c.Restarts), "ports": portsText(c.Ports), "image": shortImage(c.Image)})
			names = append(names, stackRow{stack: i, service: c.Service})
		}
	}
	return rows, names
}

// renderStacks composes the stacks' rows and note from the last read, in the
// UI's language now. On the loop.
func (h *host) renderStacks() {
	d := &h.stk
	if !d.read {
		return
	}
	rows, names := stackRows(h, d.views)
	d.rows = names
	d.model.Reset(rows)
	notes := map[string]any{"App.stacksNote": h.trf("autopanel.monitor.readAt", len(rows), d.readAt.Format("15:04:05"))}
	if d.logsOf != "" {
		notes["App.stackLogsNote"] = h.logsNote()
	}
	_ = h.p.SetMany(notes)
}

// loadStacks reads the stacks off the loop and shows them. A failed read is
// said on the status bar and in the panel's note, and the rows stay as they
// were.
func (h *host) loadStacks() {
	var views []services.View
	h.background(func(ctx context.Context) (err error) {
		views, err = h.client.Stacks(ctx)
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.error", err.Error())
			h.say(msg)
			_ = h.p.Set("App.stacksNote", msg)
			return
		}
		sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
		h.stk.views, h.stk.read, h.stk.readAt = views, true, time.Now()
		h.renderStacks()
	})
}

// openStacks opens the stacks panel and reads it.
func (h *host) openStacks() error {
	h.loadStacks()
	h.stk.shown = true
	return h.openPanel("stacks", "stacksPanel", "stacksTable")
}

// stacksClosed is the stacks panel closed: the keyboard goes back to the
// main screen.
func (h *host) stacksClosed() error {
	h.stk.shown = false
	return h.panelLeft()
}

// reloadStacks is r in the stacks panel: read it again.
func (h *host) reloadStacks() error {
	h.loadStacks()
	return nil
}

// stackAt is the stack at a row the document passed, and the service the row
// is of ("" on a stack's own row), if there is one.
func (h *host) stackAt(row int) (services.View, string, bool) {
	d := &h.stk
	if row < 0 || row >= len(d.rows) || d.rows[row].stack >= len(d.views) {
		h.say(h.tr("autopanel.stacks.none"))
		return services.View{}, "", false
	}
	return d.views[d.rows[row].stack], d.rows[row].service, true
}

// unitName names what a change was made to: "web/db" for one service of a
// stack, "web" for all of it.
func unitName(stack, service string) string {
	if service == "" {
		return stack
	}
	return stack + "/" + service
}

// addStack opens the list of the definition folders that no stack is
// registered for. With none, it says where a compose file goes.
func (h *host) addStack() error {
	var folders []services.Folder
	h.background(func(ctx context.Context) (err error) {
		folders, err = h.client.AvailableStacks(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		rows := make([]tuidecl.Row, 0, len(folders))
		for _, f := range folders {
			rows = append(rows, tuidecl.Row{"key": f.Name, "name": f.Name})
		}
		h.stk.folders = folders
		h.stk.available.Reset(rows)
		note := "autopanel.stacks.available.none"
		if len(folders) > 0 {
			note = "autopanel.stacks.available.hint"
		}
		if err := h.p.SetMany(map[string]any{"App.availableAny": len(folders) > 0, "App.availableNote": h.tr(note)}); err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		if err := h.p.Call("addStackDialog", "open"); err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
		}
	})
	return nil
}

// pickStack reviews the folder at a row of the add dialog, as a new stack.
func (h *host) pickStack(row int) error {
	if row < 0 || row >= len(h.stk.folders) {
		return nil
	}
	name := h.stk.folders[row].Name
	if err := h.p.Call("addStackDialog", "close"); err != nil {
		return err
	}
	h.checkStack(name, reviewAdd, false)
	return nil
}

// applyStack reviews the stack at row, as it is defined now. Confirming the
// review applies it; a prepared stack's starts it.
func (h *host) applyStack(row int) error {
	v, _, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	switch v.State {
	case services.LegacyRow:
		h.say(h.trf("autopanel.stacks.legacy", v.Name))
		return nil
	case services.Prepared:
		h.checkStack(v.Name, reviewStart, false)
		return nil
	}
	h.checkStack(v.Name, reviewApply, false)
	return nil
}

// checkStack asks the daemon to review a stack's definition, which changes
// nothing, and opens the review. again says that this review follows one whose
// definition changed before it was confirmed.
func (h *host) checkStack(name, mode string, again bool) {
	var r services.Review
	h.background(func(ctx context.Context) (err error) {
		r, err = h.client.CheckStack(ctx, name)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		if err := h.showReview(name, mode, r, again); err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
		}
	})
}

// refused says whether a review has a finding that stops the apply.
func refused(r services.Review) bool {
	for _, f := range r.Findings {
		if f.Severity == services.Refused {
			return true
		}
	}
	return false
}

// findingText is a finding as a sentence in the UI's language, with the
// service it is about and its detail after it. A finding this panel has no
// message for is shown by its id.
func findingText(w wording, f services.Finding) string {
	id := "autopanel.finding." + f.ID
	text := w.tr(id)
	if text == id {
		text = f.ID
	}
	if f.Service != "" {
		text += " [" + f.Service + "]"
	}
	if f.Detail != "" {
		text += ": " + f.Detail
	}
	return text
}

// findingRows are a review's findings as the review shows them: the refusals
// first, then the warnings, each in the order the daemon gave them. texts are
// the same sentences by row, for the line that shows one whole.
func findingRows(w wording, findings []services.Finding) (rows []tuidecl.Row, texts []string) {
	for _, severity := range []string{services.Refused, services.Warning} {
		level := w.tr("autopanel.review.level." + severity)
		for _, f := range findings {
			if f.Severity != severity {
				continue
			}
			text := findingText(w, f)
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(len(rows)), "level": level, "text": text})
			texts = append(texts, text)
		}
	}
	return rows, texts
}

// plannedRows are the containers a review would run, a row each.
func plannedRows(w wording, planned []services.Planned) []tuidecl.Row {
	rows := make([]tuidecl.Row, 0, len(planned))
	for _, c := range planned {
		user := c.User
		if user == "" {
			user = w.tr("autopanel.review.user.image")
		}
		memory := w.tr("autopanel.review.memory.none")
		if c.Memory > 0 {
			memory = bytesText(uint64(c.Memory))
		}
		rows = append(rows, tuidecl.Row{"key": c.Service, "service": c.Service, "image": shortImage(c.Image), "user": user,
			"network": orDash(c.Network), "ports": listText(c.Ports), "mounts": listText(c.Mounts), "memory": memory})
	}
	return rows
}

// showReview fills the review dialog with r and opens it. A refused stack's
// buttons that would apply it are disabled, and the help line says why.
func (h *host) showReview(name, mode string, r services.Review, again bool) error {
	d := &h.stk
	d.reviewName, d.reviewMode, d.review = name, mode, r
	d.planned.Reset(plannedRows(h, r.Containers))
	rows, texts := findingRows(h, r.Findings)
	d.findingTexts = texts
	d.findings.Reset(rows)

	allowed := !refused(r)
	help := h.tr("autopanel.review.help")
	if !allowed {
		help = h.tr("autopanel.review.help.refused")
	}
	if again {
		help = h.tr("autopanel.review.help.changed") + " " + help
	}
	first := ""
	if len(texts) > 0 {
		first = texts[0]
	}
	if err := h.p.SetMany(map[string]any{
		"App.reviewTitle":      h.trf("autopanel.review.title."+mode, name),
		"App.reviewSummary":    h.trf("autopanel.review.summary", shortSHA(r.SHA256), len(r.Files)),
		"App.reviewRemoves":    h.trf("autopanel.review.removes", strings.Join(r.Removes, ", ")),
		"App.reviewRemovesAny": len(r.Removes) > 0,
		"App.reviewFinding":    first,
		"App.reviewHelp":       help,
		"App.reviewGo":         h.tr("autopanel.review.go." + mode),
		"App.reviewAllowed":    allowed,
		"App.reviewNew":        mode == reviewAdd,
		"App.reviewMayPrepare": allowed && mode == reviewAdd,
	}); err != nil {
		return err
	}
	return h.p.Call("reviewDialog", "open")
}

// showFinding shows the finding at a row of the review whole, under the
// table: a row has room for the start of a long one only.
func (h *host) showFinding(row int) error {
	if row < 0 || row >= len(h.stk.findingTexts) {
		return nil
	}
	return h.p.Set("App.reviewFinding", h.stk.findingTexts[row])
}

// reviewAccept is the review confirmed: the stack is added and started,
// applied, or started, as the review said it would be.
func (h *host) reviewAccept() error {
	verb := "add" // a new stack, and a prepared one's start
	if h.stk.reviewMode == reviewApply {
		verb = "apply"
	}
	h.runReviewed(verb, "autopanel.stacks.done."+h.stk.reviewMode)
	return nil
}

// reviewPrepare is "Prepare only" on a new stack's review: its user, files
// and images are put in place, and nothing is started.
func (h *host) reviewPrepare() error {
	if h.stk.reviewMode != reviewAdd {
		return nil
	}
	h.runReviewed("prepare", "autopanel.stacks.done.prepare")
	return nil
}

// runReviewed runs verb on the reviewed stack, off the loop, giving the
// daemon the hash of the review that was on screen. The dialog has closed.
// When the definition changed since, nothing was done: it is reviewed again,
// and the new review says so. Any other end is said on the status bar, and
// the stacks are read again: an apply that failed half-way left a row.
func (h *host) runReviewed(verb, done string) {
	name, mode, r := h.stk.reviewName, h.stk.reviewMode, h.stk.review
	if name == "" || refused(r) {
		return
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return
	}
	h.busy = true
	h.say(h.trf("autopanel.stacks.working", name))
	h.background(func(ctx context.Context) error { return h.client.ApplyStack(ctx, verb, name, r.SHA256) }, func(err error) {
		h.busy = false
		switch {
		case errors.Is(err, services.ErrChanged):
			h.say(h.tr("autopanel.review.help.changed"))
			h.checkStack(name, mode, true)
			return
		case err != nil:
			h.say(h.trf("autopanel.notice.error", err.Error()))
		default:
			h.say(h.trf(done, name))
		}
		h.loadStacks()
	})
}

// change runs one change of a stack off the loop, says how it ended, and
// reads the stacks again either way.
func (h *host) change(done, name string, call func(ctx context.Context) error) {
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return
	}
	h.busy = true
	h.background(call, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
		} else {
			h.say(h.trf(done, name))
		}
		h.loadStacks()
	})
}

// stackUnit starts, stops or restarts what is at row: the row's service, or
// with whole the row's stack. A stop asks first.
func (h *host) stackUnit(action string, row int, whole bool) error {
	v, service, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	if whole {
		service = ""
	} else if service == "" {
		h.say(h.trf("autopanel.stacks.noService", v.Name))
		return nil
	}
	if action == "stop" {
		// The stop of one service stops the ones that depend on it too. Which
		// those are the list does not say, so the question names no service.
		h.stk.askName, h.stk.askService = v.Name, service
		question := h.trf("autopanel.stacks.confirm.stopStack", v.Name)
		if service != "" {
			question = h.trf("autopanel.stacks.confirm.stopService", v.Name, service)
		}
		return h.ask("autopanel.stacks.confirm.stopTitle", question, h.stopConfirmed)
	}
	h.change("autopanel.stacks.done."+action, unitName(v.Name, service), func(ctx context.Context) error {
		return h.client.StackUnit(ctx, action, v.Name, service)
	})
	return nil
}

// stopConfirmed stops what the confirmation named.
func (h *host) stopConfirmed() error {
	name, service := h.stk.askName, h.stk.askService
	h.change("autopanel.stacks.done.stop", unitName(name, service), func(ctx context.Context) error {
		return h.client.StackUnit(ctx, "stop", name, service)
	})
	return nil
}

// pullStack pulls the images of the stack at row again.
func (h *host) pullStack(row int) error {
	v, _, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return nil
	}
	h.say(h.trf("autopanel.stacks.working", v.Name))
	h.change("autopanel.stacks.done.pull", v.Name, func(ctx context.Context) error {
		return h.client.PullStack(ctx, v.Name, "")
	})
	return nil
}

// removeStack asks before removing the stack at row; with purge, its
// directory too.
func (h *host) removeStack(row int, purge bool) error {
	v, _, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	h.stk.askName, h.stk.askPurge = v.Name, purge
	question := "autopanel.stacks.confirm.remove"
	if purge {
		question = "autopanel.stacks.confirm.purge"
	}
	return h.ask("autopanel.stacks.confirm.title", h.trf(question, v.Name, orDash(v.User)), h.removeStackConfirmed)
}

// removeStackConfirmed removes the stack the confirmation named.
func (h *host) removeStackConfirmed() error {
	name, purge := h.stk.askName, h.stk.askPurge
	done := "autopanel.stacks.done.remove"
	if purge {
		done = "autopanel.stacks.done.purge"
	}
	h.change(done, name, func(ctx context.Context) error { return h.client.RemoveStack(ctx, name, purge) })
	return nil
}

// logsNote says whose lines the log panel shows, how many, and when they
// were read.
func (h *host) logsNote() string {
	d := &h.stk
	return h.trf("autopanel.stacks.logs.note", unitName(d.logsOf, d.logsService), d.logLines, d.logsAt.Format("15:04:05"))
}

// loadLogs reads the newest journal lines of a stack, or of one service of
// it, and shows them, oldest first.
func (h *host) loadLogs(name, service string) {
	var lines []string
	h.background(func(ctx context.Context) (err error) {
		lines, err = h.client.StackLogs(ctx, name, service)
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.error", err.Error())
			h.say(msg)
			_ = h.p.Set("App.stackLogsNote", msg)
			return
		}
		rows := make([]tuidecl.Row, 0, len(lines))
		for i, l := range lines {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "line": l})
		}
		h.stk.logs.Reset(rows)
		h.stk.logsOf, h.stk.logsService, h.stk.logLines, h.stk.logsAt = name, service, len(lines), time.Now()
		_ = h.p.Set("App.stackLogsNote", h.logsNote())
	})
}

// openLogs opens the log panel on the service at row, or on the whole stack
// when the row has no service.
func (h *host) openLogs(row int) error {
	v, service, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	if v.Name != h.stk.logsOf || service != h.stk.logsService {
		h.stk.logs.Reset(nil) // never one service's lines under another's name
	}
	h.loadLogs(v.Name, service)
	return h.openPanel("stackLogs", "stackLogsPanel", "stackLogsTable")
}

// reloadLogs is r in the log panel: read the same lines again.
func (h *host) reloadLogs() error {
	if h.stk.logsOf != "" {
		h.loadLogs(h.stk.logsOf, h.stk.logsService)
	}
	return nil
}
