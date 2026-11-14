package ui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// THE STACKS — Services › Stacks, a panel of two panes. On the left each
// stack, and under it each of its containers; on the right the selected one
// whole. What a button does is to the selected row: a container's row acts on
// that service, a stack's row on the whole stack. Each change is a verb of the
// daemon's, which records it before it runs it, and the stacks are read
// again after it, and with the screen while the panel is open.
//
// A stack is added from the file browser (browse.go), and added or applied
// only after its review: what it would run, and what the policy refuses or
// warns of. A stack imported from a folder whose definition changed since is
// marked, and Update from source copies it again and opens the review.

// The reviews the panel shows, by what confirming one does.
const (
	reviewAdd   = "add"   // a new stack: services.add, or services.prepare
	reviewApply = "apply" // a registered stack: services.apply
	reviewStart = "start" // a prepared stack: services.add starts it
)

// changedMark follows the name of a stack whose definition changed since it
// was applied.
const changedMark = "*"

// stackRow is what a row of the stacks list names: a stack, and one service
// of it, or "" on the stack's own row.
type stackRow struct {
	stack   int // the stack's place in stacks.views
	service string
}

// reviewRow is what a row of the review's list names: a container, or a
// finding.
type reviewRow struct {
	container int // the container's place in the review, or -1
	finding   int // the finding's place in findingTexts, or -1
}

// stacks is the stacks panel's models and what they were last filled from.
type stacks struct {
	model  *tuidecl.ListModel // App.stacks: the list's rows
	logs   *tuidecl.ListModel // App.stackLogs: journal lines
	review *tuidecl.ListModel // App.reviewRows: the review's containers and findings

	views  []services.View // the stacks, as the daemon gave them
	rows   []stackRow      // the list's rows, by row
	read   bool            // the stacks have been read once
	readAt time.Time
	at     int // the row under the list's cursor

	logsOf      string // the stack the log panel shows
	logsService string // and the service of it, or "" for all
	logLines    int
	logsAt      time.Time

	reviewName   string          // the stack the review is of
	reviewMode   string          // reviewAdd, reviewApply or reviewStart
	reviewed     services.Review // the review on screen
	again        bool            // the review follows one whose definition changed
	reviewRows   []reviewRow     // the review list's rows, by row
	findingTexts []string        // the review's findings, whole, in the list's order
	findingLevel []string        // and each one's level
	reviewAt     int
}

func newStacks() stacks {
	return stacks{
		model:  tuidecl.NewListModel("key", "name", "state", "health"),
		logs:   tuidecl.NewListModel("key", "line"),
		review: tuidecl.NewListModel("key", "kind", "name", "text"),
	}
}

// state is the stacks' part of the App singleton's state.
func (d *stacks) state() map[string]any {
	return map[string]any{
		"App.stacks":            d.model,
		"App.stackLogs":         d.logs,
		"App.reviewRows":        d.review,
		"App.stacksTitle":       "",
		"App.stacksAt":          0,
		"App.stackDetail":       "",
		"App.stackCanUpdate":    false,
		"App.stackLogsTitle":    "",
		"App.reviewTitle":       "",
		"App.reviewSummary":     "",
		"App.reviewNotice":      "",
		"App.reviewNoticeShown": false,
		"App.reviewRemoves":     "",
		"App.reviewRemovesAny":  false,
		"App.reviewDetail":      "",
		"App.reviewGo":          englishText("autopanel.button.review.apply"),
		"App.reviewAllowed":     false,
		"App.reviewNew":         false,
		"App.reviewMayPrepare":  false,
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

// shortImage is an image's reference as the list shows it: without Docker
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
	sum = strings.TrimPrefix(sum, "sha256:")
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
		return w.trf("autopanel.value.stacks.incomplete", orDash(v.Step))
	case string(services.Deploying), string(services.Removing), services.Prepared, services.LegacyRow:
		return w.tr("autopanel.value.stacks." + v.State)
	}
	return v.State
}

// containerState is a container's state in a list. One a person stopped is
// "stopped", whatever systemd says of its unit: systemd may call it failed. A
// stack that is not simply deployed says so first.
func containerState(w wording, v services.View, c services.Container) string {
	state := unitState(c)
	if c.Stopped {
		state = w.tr("autopanel.value.stacks.stopped")
	}
	if of := stackState(w, v); of != "" {
		return of + " · " + state
	}
	return state
}

// sourceState says where a stack's source stands: "" for a stack that was not
// imported, or whose source is as it was imported.
func sourceState(w wording, v services.View) string {
	if v.Source == nil {
		return ""
	}
	switch v.Source.State {
	case "changed":
		return w.tr("autopanel.value.source.changed")
	case "missing":
		return w.tr("autopanel.value.source.missing")
	}
	return ""
}

// stackName is a stack's name in the list, marked when its definition
// changed since it was applied.
func stackName(v services.View) string {
	if v.Changed {
		return v.Name + changedMark
	}
	return v.Name
}

// stackRows are the stacks list's rows: each stack, its state in words and
// its source's when that changed, then each of its containers, indented.
// names says which stack and service each row is.
func stackRows(w wording, views []services.View) (rows []tuidecl.Row, names []stackRow) {
	for i, v := range views {
		state := stackState(w, v)
		if state == "" {
			state = w.tr("autopanel.value.stacks.deployed")
		}
		if src := sourceState(w, v); src != "" {
			state += " · " + src
		}
		rows = append(rows, tuidecl.Row{"key": v.Name + "/", "name": stackName(v), "state": state, "health": ""})
		names = append(names, stackRow{stack: i})
		for _, c := range v.Containers {
			rows = append(rows, tuidecl.Row{"key": v.Name + "/" + c.Service, "name": "  " + c.Service,
				"state": containerState(w, v, c), "health": orDash(c.Health)})
			names = append(names, stackRow{stack: i, service: c.Service})
		}
	}
	return rows, names
}

// cpuText is the processor time a container has used, in seconds.
func cpuText(nanos uint64) string {
	if nanos == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f s", float64(nanos)/1e9)
}

// sourceLines are a stack's source facts: where it was imported from, when,
// and whether that changed since.
func sourceLines(w wording, v services.View) [][2]string {
	if v.Source == nil {
		return [][2]string{{"autopanel.label.stack.source", w.tr("autopanel.value.source.none")}}
	}
	state := w.tr("autopanel.value.source.same")
	if s := sourceState(w, v); s != "" {
		state = s
	}
	return [][2]string{
		{"autopanel.label.stack.source", v.Source.Path},
		{"autopanel.label.stack.imported", stamp(v.Source.ImportedAt)},
		{"autopanel.label.stack.sourceState", state},
	}
}

// stackDetail is the selected row whole: a container's, or its stack's.
func stackDetail(w wording, v services.View, service string) string {
	if service == "" {
		def := shortSHA(v.SHA256)
		if v.Changed {
			def = w.trf("autopanel.value.stacks.changedSince", def)
		}
		state := stackState(w, v)
		if state == "" {
			state = w.tr("autopanel.value.stacks.deployed")
		}
		lines := [][2]string{
			{"autopanel.label.stack.name", v.Name},
			{"autopanel.label.stack.state", state},
			{"autopanel.label.stack.user", orDash(v.User)},
			{"autopanel.label.stack.definition", def},
			{"autopanel.label.stack.containers", strconv.Itoa(len(v.Containers))},
		}
		return facts(w, append(lines, sourceLines(w, v)...)...)
	}
	for _, c := range v.Containers {
		if c.Service != service {
			continue
		}
		memory := "-"
		if c.MemoryBytes > 0 {
			memory = bytesText(c.MemoryBytes)
		}
		since := "-"
		if c.Since > 0 {
			since = stamp(c.Since)
		}
		lines := [][2]string{
			{"autopanel.label.stack.service", w.trf("autopanel.value.stacks.serviceOf", c.Service, v.Name)},
			{"autopanel.label.stack.image", orDash(c.Image)},
			{"autopanel.label.stack.digest", orDash(c.Digest)},
			{"autopanel.label.stack.ports", portsText(c.Ports)},
			{"autopanel.label.stack.state", containerState(w, v, c)},
			{"autopanel.label.stack.health", orDash(c.Health)},
			{"autopanel.label.stack.restarts", strconv.Itoa(c.Restarts)},
			{"autopanel.label.stack.since", since},
			{"autopanel.label.stack.cpu", cpuText(c.CPUNanos)},
			{"autopanel.label.stack.memory", memory},
		}
		return facts(w, append(lines, sourceLines(w, v)...)...)
	}
	return ""
}

// setStacks keeps a read of the stacks, by name, and shows it.
func (h *host) setStacks(views []services.View) {
	sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	h.stk.views, h.stk.read, h.stk.readAt = views, true, time.Now()
	h.wid.stacksErr = nil
	h.renderStacks()
}

// renderStacks composes the stacks' rows, title and details from the last
// read, in the UI's language now. On the loop.
func (h *host) renderStacks() {
	d := &h.stk
	if d.read {
		rows, names := stackRows(h, d.views)
		d.rows = names
		d.model.Reset(rows)
	}
	title := h.tr("autopanel.title.list.stacks")
	if h.wid.stacksErr != nil {
		title = h.trf("autopanel.title.list.failed", title, h.wid.stacksErr.Error())
	} else if d.read {
		title = h.trf("autopanel.title.list.count", title, len(d.views), d.readAt.Format("15:04:05"))
	}
	vals := map[string]any{"App.stacksTitle": title}
	for k, v := range h.stackSelection() {
		vals[k] = v
	}
	if d.logsOf != "" {
		vals["App.stackLogsTitle"] = h.logsTitle()
	}
	_ = h.p.SetMany(vals)
	h.renderStackSummary()
}

// stackSelection is the details pane and the buttons for the row under the
// list's cursor.
func (h *host) stackSelection() map[string]any {
	v, service, ok := h.stackRowAt(h.stk.at)
	if !ok {
		return map[string]any{"App.stackDetail": "", "App.stackCanUpdate": false}
	}
	return map[string]any{"App.stackDetail": stackDetail(h, v, service),
		"App.stackCanUpdate": v.Source != nil && v.Source.State == "changed"}
}

// stackMoved is the stacks list's cursor moved.
func (h *host) stackMoved(row int) error {
	h.stk.at = row
	return h.p.SetMany(h.stackSelection())
}

// loadStacks reads the stacks off the loop and shows them. A failed read is
// said in the list's title, and the rows stay as they were.
func (h *host) loadStacks() {
	var views []services.View
	h.background(func(ctx context.Context) (err error) {
		views, err = h.client.Stacks(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.wid.stacksErr = err
			h.renderStacks()
			return
		}
		h.setStacks(views)
	})
}

// openStacks opens the stacks panel and reads it.
func (h *host) openStacks() error {
	h.loadStacks()
	return h.openPanel("stacks")
}

// openStackAt is Enter on the stacks widget: the panel, on that container.
func (h *host) openStackAt(row int) error {
	if row >= 0 && row < h.wid.stacks.Len() {
		key := h.wid.stacks.Key(tuidecl.Index{Row: row})
		for i, r := range h.stk.rows {
			if r.stack < len(h.stk.views) && h.stk.views[r.stack].Name+"/"+r.service == key {
				h.stk.at = i
				_ = h.p.Set("App.stacksAt", -1) // through another value: the cursor may have moved since
				_ = h.p.Set("App.stacksAt", i)
				_ = h.p.SetMany(h.stackSelection())
			}
		}
	}
	return h.openStacks()
}

// stackRowAt is the stack at a row of the list, and the service the row is of
// ("" on a stack's own row), if there is one.
func (h *host) stackRowAt(row int) (services.View, string, bool) {
	d := &h.stk
	if row < 0 || row >= len(d.rows) || d.rows[row].stack >= len(d.views) {
		return services.View{}, "", false
	}
	return d.views[d.rows[row].stack], d.rows[row].service, true
}

// stackAt is stackRowAt, saying so when there is no stack there.
func (h *host) stackAt(row int) (services.View, string, bool) {
	v, service, ok := h.stackRowAt(row)
	if !ok {
		h.say(h.tr("autopanel.notice.stacks.none"))
	}
	return v, service, ok
}

// unitName names what a change was made to: "web/db" for one service of a
// stack, "web" for all of it.
func unitName(stack, service string) string {
	if service == "" {
		return stack
	}
	return stack + "/" + service
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
		h.say(h.trf("autopanel.notice.stacks.legacy", v.Name))
		return nil
	case services.Prepared:
		h.checkStack(v.Name, reviewStart, false)
		return nil
	}
	h.checkStack(v.Name, reviewApply, false)
	return nil
}

// updateFromSource copies the definition of the stack at row from its source
// again, then opens its review: what runs changes only once that is
// confirmed.
func (h *host) updateFromSource(row int) error {
	v, _, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	switch {
	case v.Source == nil:
		h.say(h.trf("autopanel.notice.stacks.noSource", v.Name))
		return nil
	case v.Source.State == "missing":
		h.say(h.trf("autopanel.notice.stacks.sourceMissing", v.Name, v.Source.Path))
		return nil
	case v.Source.State != "changed":
		h.say(h.trf("autopanel.notice.stacks.sourceSame", v.Name))
		return nil
	}
	name := v.Name
	h.say(h.trf("autopanel.notice.stacks.working", name))
	h.change(func(ctx context.Context) error {
		_, err := h.client.ReimportStack(ctx, name)
		return err
	}, func() {
		h.say(h.trf("autopanel.notice.stacks.reimported", name))
		h.loadStacks()
		h.checkStack(name, reviewApply, false)
	})
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
			h.failed(err)
			return
		}
		if err := h.showReview(name, mode, r, again); err != nil {
			h.failed(err)
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
	id := "autopanel.finding.review." + f.ID
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

// orderedFindings are a review's findings as the review shows them: the
// refusals first, then the warnings, each in the order the daemon gave them;
// each one's level, and its sentence.
func orderedFindings(w wording, findings []services.Finding) (levels, texts []string) {
	for _, severity := range []string{services.Refused, services.Warning} {
		level := w.tr("autopanel.value.review." + severity)
		for _, f := range findings {
			if f.Severity == severity {
				levels = append(levels, level)
				texts = append(texts, findingText(w, f))
			}
		}
	}
	return levels, texts
}

// reviewList is the review's list: each container it would run, then each
// finding, refusals first.
func reviewList(w wording, r services.Review) (rows []tuidecl.Row, names []reviewRow, levels, texts []string) {
	kind := w.tr("autopanel.value.review.container")
	for i, c := range r.Containers {
		rows = append(rows, tuidecl.Row{"key": "c" + strconv.Itoa(i), "kind": kind, "name": c.Service, "text": shortImage(c.Image)})
		names = append(names, reviewRow{container: i, finding: -1})
	}
	levels, texts = orderedFindings(w, r.Findings)
	for i, t := range texts {
		rows = append(rows, tuidecl.Row{"key": "f" + strconv.Itoa(i), "kind": levels[i], "name": "", "text": t})
		names = append(names, reviewRow{container: -1, finding: i})
	}
	return rows, names, levels, texts
}

// plannedDetail is a container a review would run, whole.
func plannedDetail(w wording, c services.Planned) string {
	user := c.User
	if user == "" {
		user = w.tr("autopanel.value.review.imageUser")
	}
	memory := w.tr("autopanel.value.review.noMemoryLimit")
	if c.Memory > 0 {
		memory = bytesText(uint64(c.Memory))
	}
	yes := func(b bool) string {
		if b {
			return w.tr("autopanel.value.review.yes")
		}
		return w.tr("autopanel.value.review.no")
	}
	return facts(w,
		[2]string{"autopanel.label.review.service", c.Service},
		[2]string{"autopanel.label.review.image", orDash(c.Image)},
		[2]string{"autopanel.label.review.user", user},
		[2]string{"autopanel.label.review.network", orDash(c.Network)},
		[2]string{"autopanel.label.review.ports", listText(c.Ports)},
		[2]string{"autopanel.label.review.mounts", listText(c.Mounts)},
		[2]string{"autopanel.label.review.memory", memory},
		[2]string{"autopanel.label.review.readOnly", yes(c.ReadOnly)},
		[2]string{"autopanel.label.review.restart", orDash(c.Restart)},
		[2]string{"autopanel.label.review.dependsOn", listText(c.DependsOn)},
		[2]string{"autopanel.label.review.capAdd", listText(c.CapAdd)},
		[2]string{"autopanel.label.review.capDrop", listText(c.CapDrop)})
}

// reviewDetailAt is the review list's row whole.
func (h *host) reviewDetailAt(row int) string {
	d := &h.stk
	if row < 0 || row >= len(d.reviewRows) {
		return ""
	}
	r := d.reviewRows[row]
	if r.container >= 0 && r.container < len(d.reviewed.Containers) {
		return plannedDetail(h, d.reviewed.Containers[r.container])
	}
	if r.finding >= 0 && r.finding < len(d.findingTexts) {
		return facts(h, [2]string{"autopanel.label.review.level", d.findingLevel[r.finding]}) + "\n\n" + d.findingTexts[r.finding]
	}
	return ""
}

// showReview fills the review dialog with r and opens it. A refused stack's
// buttons that would apply it are disabled, and the dialog says why.
func (h *host) showReview(name, mode string, r services.Review, again bool) error {
	d := &h.stk
	d.reviewName, d.reviewMode, d.reviewed, d.again, d.reviewAt = name, mode, r, again, 0
	if err := h.renderReview(); err != nil {
		return err
	}
	return h.p.Call("reviewDialog", "open")
}

// renderReview composes the review on screen, in the UI's language now.
func (h *host) renderReview() error {
	d := &h.stk
	if d.reviewName == "" {
		return nil
	}
	r := d.reviewed
	rows, names, levels, texts := reviewList(h, r)
	d.reviewRows, d.findingLevel, d.findingTexts = names, levels, texts
	d.review.Reset(rows)
	allowed := !refused(r)
	var notice []string
	if d.again {
		notice = append(notice, h.tr("autopanel.notice.review.changed"))
	}
	if !allowed {
		notice = append(notice, h.tr("autopanel.notice.review.refused"))
	}
	return h.p.SetMany(map[string]any{
		"App.reviewTitle":       h.trf("autopanel.title.review."+d.reviewMode, d.reviewName),
		"App.reviewSummary":     h.trf("autopanel.value.review.summary", shortSHA(r.SHA256), len(r.Files), len(r.Containers)),
		"App.reviewNotice":      strings.Join(notice, " "),
		"App.reviewNoticeShown": len(notice) > 0,
		"App.reviewRemoves":     h.trf("autopanel.value.review.removes", strings.Join(r.Removes, ", ")),
		"App.reviewRemovesAny":  len(r.Removes) > 0,
		"App.reviewDetail":      h.reviewDetailAt(d.reviewAt),
		"App.reviewGo":          h.tr("autopanel.button.review." + d.reviewMode),
		"App.reviewAllowed":     allowed,
		"App.reviewNew":         d.reviewMode == reviewAdd,
		"App.reviewMayPrepare":  allowed && d.reviewMode == reviewAdd,
	})
}

// reviewMoved is the review list's cursor moved: the right pane shows that
// row whole.
func (h *host) reviewMoved(row int) error {
	h.stk.reviewAt = row
	return h.p.Set("App.reviewDetail", h.reviewDetailAt(row))
}

// reviewAccept is the review confirmed: the stack is added and started,
// applied, or started, as the review said it would be.
func (h *host) reviewAccept() error {
	verb := "add" // a new stack, and a prepared one's start
	if h.stk.reviewMode == reviewApply {
		verb = "apply"
	}
	h.runReviewed(verb, "autopanel.notice.stacks."+h.stk.reviewMode+"Done")
	return nil
}

// reviewPrepare is "Prepare only" on a new stack's review: its user, files
// and images are put in place, and nothing is started.
func (h *host) reviewPrepare() error {
	if h.stk.reviewMode != reviewAdd {
		return nil
	}
	h.runReviewed("prepare", "autopanel.notice.stacks.prepareDone")
	return nil
}

// runReviewed runs verb on the reviewed stack, off the loop, giving the
// daemon the hash of the review that was on screen. The dialog has closed.
// When the definition changed since, nothing was done: it is reviewed again,
// and the new review says so. Any other end is said on the status bar, and
// the stacks are read again: an apply that failed half-way left a row.
func (h *host) runReviewed(verb, done string) {
	name, mode, r := h.stk.reviewName, h.stk.reviewMode, h.stk.reviewed
	if name == "" || refused(r) {
		return
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return
	}
	h.busy = true
	h.say(h.trf("autopanel.notice.stacks.working", name))
	h.background(func(ctx context.Context) error { return h.client.ApplyStack(ctx, verb, name, r.SHA256) }, func(err error) {
		h.busy = false
		switch {
		case errors.Is(err, services.ErrChanged):
			h.say(h.tr("autopanel.notice.review.changed"))
			h.checkStack(name, mode, true)
			return
		case err != nil:
			h.failed(err)
		default:
			h.say(h.trf(done, name))
		}
		h.loadStacks()
	})
}

// stackChange runs one change of a stack off the loop, says how it ended, and
// reads the stacks again either way.
func (h *host) stackChange(done, name string, call func(ctx context.Context) error) {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return
	}
	h.busy = true
	h.background(call, func(err error) {
		h.busy = false
		if err != nil {
			h.failed(err)
		} else {
			h.say(h.trf(done, name))
		}
		h.loadStacks()
	})
}

// stackUnit starts, stops or restarts what is at row: the row's service, or
// the whole stack on its own row. A stop asks first.
func (h *host) stackUnit(action string, row int) error {
	v, service, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	name := v.Name
	if action == "stop" {
		// The stop of one service stops the ones that depend on it too. Which
		// those are the list does not say, so the question names no service.
		question := h.trf("autopanel.question.stacks.stopStack", name)
		if service != "" {
			question = h.trf("autopanel.question.stacks.stopService", name, service)
		}
		return h.ask("autopanel.title.confirm.stop", question, func() error {
			h.stackChange("autopanel.notice.stacks.stopDone", unitName(name, service), func(ctx context.Context) error {
				return h.client.StackUnit(ctx, "stop", name, service)
			})
			return nil
		})
	}
	h.stackChange("autopanel.notice.stacks."+action+"Done", unitName(name, service), func(ctx context.Context) error {
		return h.client.StackUnit(ctx, action, name, service)
	})
	return nil
}

// pullStack pulls the images of what is at row again: the row's service, or
// the whole stack on its own row.
func (h *host) pullStack(row int) error {
	v, service, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return nil
	}
	name := v.Name
	h.say(h.trf("autopanel.notice.stacks.working", unitName(name, service)))
	h.stackChange("autopanel.notice.stacks.pullDone", unitName(name, service), func(ctx context.Context) error {
		return h.client.PullStack(ctx, name, service)
	})
	return nil
}

// removeStack asks before removing the stack at row: No, Remove, or Remove
// with its directory.
func (h *host) removeStack(row int) error {
	v, _, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	name := v.Name
	remove := func(purge bool) func() error {
		return func() error {
			done := "autopanel.notice.stacks.removeDone"
			if purge {
				done = "autopanel.notice.stacks.purgeDone"
			}
			h.stackChange(done, name, func(ctx context.Context) error { return h.client.RemoveStack(ctx, name, purge) })
			return nil
		}
	}
	return h.askOr("autopanel.title.confirm.removeStack", h.trf("autopanel.question.stacks.remove", name, orDash(v.User)),
		"autopanel.button.confirm.purge", remove(true), remove(false))
}

// logsTitle says whose lines the log panel shows, how many, and when they
// were read.
func (h *host) logsTitle() string {
	d := &h.stk
	return h.trf("autopanel.title.list.journal", unitName(d.logsOf, d.logsService), d.logLines, d.logsAt.Format("15:04:05"))
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
			_ = h.p.Set("App.stackLogsTitle", h.trf("autopanel.title.list.failed", unitName(name, service), err.Error()))
			return
		}
		rows := make([]tuidecl.Row, 0, len(lines))
		for i, l := range lines {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "line": l})
		}
		h.stk.logs.Reset(rows)
		h.stk.logsOf, h.stk.logsService, h.stk.logLines, h.stk.logsAt = name, service, len(lines), time.Now()
		_ = h.p.Set("App.stackLogsTitle", h.logsTitle())
	})
}

// openLogs opens the log panel on the service at row, or on the whole stack
// on its own row.
func (h *host) openLogs(row int) error {
	v, service, ok := h.stackAt(row)
	if !ok {
		return nil
	}
	if v.Name != h.stk.logsOf || service != h.stk.logsService {
		h.stk.logs.Reset(nil) // never one service's lines under another's name
	}
	h.loadLogs(v.Name, service)
	return h.openPanel("stackLogs")
}

// reloadLogs is Reload in the log panel: read the same lines again.
func (h *host) reloadLogs() error {
	if h.stk.logsOf != "" {
		h.loadLogs(h.stk.logsOf, h.stk.logsService)
	}
	return nil
}
