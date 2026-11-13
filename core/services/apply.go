package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// REVIEW, THEN APPLY. A review stages the definition (reads each of its files
// once, into a folder only root reaches) and answers what it holds. An apply
// stages it again, is refused unless the two are the same, and then works
// from the staged copy alone: what was reviewed is what runs.

// Planned is a container as a review shows it, before anything is made.
type Planned struct {
	Service   string   `json:"service"`
	Image     string   `json:"image"`
	User      string   `json:"user"`    // "991:991", or "" for the image's own
	Network   string   `json:"network"` // "private" or "host"
	Ports     []string `json:"ports"`
	Mounts    []string `json:"mounts"`
	Memory    int64    `json:"memory"` // bytes; 0 for no limit
	ReadOnly  bool     `json:"read_only"`
	Restart   string   `json:"restart"`
	DependsOn []string `json:"depends_on"`
	CapAdd    []string `json:"cap_add"`
	CapDrop   []string `json:"cap_drop"`
}

// Review is services.check's answer.
type Review struct {
	SHA256     string    `json:"sha256"` // what an apply must be given
	Files      []Input   `json:"files"`
	Containers []Planned `json:"containers"`
	Findings   []Finding `json:"findings"`
	Removes    []string  `json:"removes"` // the services an apply would stop and remove
}

// reviewed is a staged definition, read and checked.
type reviewed struct {
	stack    Stack
	manifest Manifest
	findings []Finding
}

// base is everything a stack may have on the host: what was applied, and what
// an apply that did not finish may have made.
func base(svc Service) (Applied, []string) {
	if svc.Pending == nil {
		return svc.Applied, svc.Applied.managed()
	}
	return union(svc.Applied, nil, svc.Pending.Applied, svc.Pending.Managed)
}

// review stages name's definition and checks it. The caller holds the stack's
// lock, and the ports lock when what it does next depends on the ports being
// free.
func (m *Module) review(ctx context.Context, name string, svc Service) (reviewed, error) {
	compose, envText, err := m.host.Stage(ctx, name)
	if err != nil {
		return reviewed{}, err
	}
	env, bad := ParseEnv(envText)
	st, findings := Parse(compose, env)
	for _, line := range bad {
		findings = append(findings, Finding{ID: "bad-env-line", Severity: Refused, Detail: ".env line " + strconv.Itoa(line)})
	}
	managed, data := managedPaths(st), dataPaths(st)
	files, missing, links, err := m.host.StagePaths(ctx, name, managed)
	if err != nil {
		return reviewed{}, err
	}
	for _, p := range missing {
		findings = append(findings, Finding{ID: "missing-file", Severity: Refused, Detail: short(p)})
	}
	present, more, err := m.host.Look(ctx, name, append(append([]string{}, managed...), data...))
	if err != nil {
		return reviewed{}, err
	}
	before, managedBefore := base(svc)
	facts := Facts{Data: before.Data, Managed: managedBefore, Present: present, Links: append(links, more...)}
	all, err := m.store.All(ctx)
	if err != nil {
		return reviewed{}, err
	}
	for _, o := range all {
		if o.Name == name {
			continue
		}
		theirs, _ := base(o)
		for _, p := range theirs.ports() {
			facts.Taken = append(facts.Taken, Claim{Stack: o.Name, PortUse: p})
		}
	}
	if facts.Listening, err = m.host.Listening(ctx, name); err != nil {
		return reviewed{}, err
	}
	findings = append(findings, check(st, facts)...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Severity < findings[j].Severity })
	return reviewed{stack: st, manifest: NewManifest(files), findings: findings}, nil
}

func planned(s Spec) Planned {
	p := Planned{Service: s.Name, Image: s.Image, Network: "private", Memory: s.MemLimit, ReadOnly: s.ReadOnly, Restart: s.Restart,
		DependsOn: s.DependsOn, CapAdd: s.CapAdd, CapDrop: s.CapDrop, Ports: []string{}, Mounts: []string{}}
	if s.HasUser {
		p.User = strconv.Itoa(s.UID) + ":" + strconv.Itoa(s.GID)
	}
	if s.HostNetwork {
		p.Network = "host"
	}
	for _, pub := range s.Ports {
		if s.HostNetwork {
			p.Ports = append(p.Ports, portText(pub.Use()))
		} else {
			p.Ports = append(p.Ports, publish(pub))
		}
	}
	for _, mnt := range s.Volumes {
		text := mnt.Source + " → " + mnt.Target
		switch {
		case mnt.Named:
			text += " (volume)"
		case mnt.ReadOnly:
			text += " (read-only)"
		default:
			text += " (data)"
		}
		p.Mounts = append(p.Mounts, text)
	}
	for _, list := range []*[]string{&p.DependsOn, &p.CapAdd, &p.CapDrop} {
		if *list == nil {
			*list = []string{}
		}
	}
	return p
}

func (m *Module) check(ctx context.Context, r Ref) (Review, error) {
	if !ValidName(r.Name) {
		return Review{}, ErrBadName
	}
	defer m.lock(r.Name)()
	svc, err := m.store.Get(ctx, r.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		svc = Service{Name: r.Name}
	case err != nil:
		return Review{}, err
	case svc.Legacy:
		return Review{}, ErrLegacy
	}
	rev, err := m.review(ctx, r.Name, svc)
	if err != nil {
		return Review{}, err
	}
	out := Review{SHA256: rev.manifest.SHA256, Files: rev.manifest.Files, Findings: rev.findings, Containers: []Planned{}, Removes: []string{}}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	now := map[string]bool{}
	for _, s := range rev.stack.Services {
		out.Containers = append(out.Containers, planned(s))
		now[s.Name] = true
	}
	for _, u := range svc.Applied.Units {
		if u.Kind == KindContainer && !now[u.Service] {
			out.Removes = append(out.Removes, u.Service)
		}
	}
	return out, nil
}

func (m *Module) prepare(ctx context.Context, p Accept) (View, error) {
	return m.run(ctx, p, true, true)
}

func (m *Module) add(ctx context.Context, p Accept) (View, error) {
	return m.run(ctx, p, true, false)
}

func (m *Module) applyVerb(ctx context.Context, p Accept) (View, error) {
	return m.run(ctx, p, false, false)
}

// run is prepare, add and apply. first says the stack may be new: add and
// prepare register it, and refuse one an apply has already finished for.
func (m *Module) run(ctx context.Context, p Accept, first, prepareOnly bool) (View, error) {
	if !ValidName(p.Name) {
		return View{}, ErrBadName
	}
	if err := m.podman(ctx); err != nil {
		return View{}, err
	}
	defer m.lock(p.Name)()
	svc, err := m.store.Get(ctx, p.Name)
	switch {
	case errors.Is(err, ErrNotFound) && first:
		svc = Service{Name: p.Name, State: Deploying}
	case err != nil:
		return View{}, err
	case svc.State == Removing:
		return View{}, ErrBusy
	case svc.Legacy:
		return View{}, ErrLegacy
	case first && len(svc.Applied.Units) > 0:
		return View{}, ErrDuplicate
	}
	isNew := errors.Is(err, ErrNotFound)

	// The ports are claimed under one lock: the check that finds them free
	// and the record that claims them are one step to every other stack.
	m.ports.Lock()
	rev, err := m.review(ctx, p.Name, svc)
	if err == nil && rev.manifest.SHA256 != p.Accept {
		err = ErrChanged
	}
	if err == nil {
		for _, f := range rev.findings {
			if f.Severity == Refused {
				err = with(ErrRefused, strings.TrimSpace(f.ID+" "+f.Service+" "+f.Detail))
				break
			}
		}
	}
	if err != nil {
		m.ports.Unlock()
		return View{}, err
	}
	before, managedBefore := base(svc)
	next, _ := units(p.Name, rev.stack, nil)
	plan := Applied{Manifest: rev.manifest, Units: next, Data: dataPaths(rev.stack), Roots: managedPaths(rev.stack)}
	pend := Pending{Step: "user"}
	pend.Applied, pend.Managed = union(before, managedBefore, plan, nil)
	// The row first, then the plan: a crash from here on leaves a row the
	// panel shows, with everything the apply may have made on record.
	if isNew {
		err = m.store.Add(ctx, p.Name)
	}
	if err == nil {
		err = m.store.SetPending(ctx, p.Name, pend)
	}
	m.ports.Unlock()
	if err != nil {
		return View{}, err
	}
	svc.Pending = &pend

	m.working(p.Name, true)
	defer m.working(p.Name, false)
	// A step that fails says which, and why, to the caller: its error is the
	// host's own (a tool's message), cut short.
	fail := func(step string, err error) (View, error) {
		pend.Step = step
		_ = m.store.SetPending(context.WithoutCancel(ctx), p.Name, pend)
		return View{}, &detailed{err: fmt.Errorf("%w: %s, at %q: %v", ErrIncomplete, p.Name, step, err), detail: step + ": " + reason(err)}
	}
	if err := m.host.EnsureUser(ctx, p.Name); err != nil {
		return fail("user", err)
	}

	// Only an image whose reference is new or changed is pulled. One that is
	// as it was runs the digest already recorded: an apply does not move a
	// tag, and needs no registry for what it has.
	digests := map[string]string{}
	for _, s := range rev.stack.Services {
		if u, ok := before.unit(s.Name); ok && u.Image == s.Image && u.Digest != "" {
			repo, _ := ImageRef(s.Image)
			if has, err := m.host.HasImage(ctx, p.Name, repo+"@"+u.Digest); err != nil {
				return fail("pull", err)
			} else if has {
				digests[s.Name] = u.Digest
				continue
			}
		}
		d, err := m.host.Pull(ctx, p.Name, s.Image)
		if err != nil {
			return fail("pull", err)
		}
		digests[s.Name] = d
	}
	next, generated := units(p.Name, rev.stack, digests)
	plan.Units = next
	pend.Applied, pend.Managed = union(before, managedBefore, plan, nil)

	// What was managed and no longer is goes: a file the definition lost, and
	// a folder it no longer mounts.
	commit := Commit{Managed: rev.manifest.paths(), Data: plan.Data, Generated: generated}
	have := map[string]bool{}
	for _, f := range plan.managed() {
		have[f] = true
	}
	for _, f := range managedBefore {
		if !have[f] {
			commit.Stale = append(commit.Stale, f)
		}
	}
	if prepareOnly {
		if err := m.host.Commit(ctx, p.Name, commit); err != nil {
			return fail("files", err)
		}
		pend.Step, pend.Prepared = "prepared", true
		if err := m.store.SetPending(ctx, p.Name, pend); err != nil {
			return View{}, err
		}
		svc.Pending = &pend
		m.working(p.Name, false)
		return m.view(ctx, svc), nil
	}

	// What the new file no longer has, and what an apply that failed wrote
	// and this one does not want: stopped, and its unit deleted, so that a
	// boot cannot bring it back.
	keep := map[string]bool{}
	for _, u := range next {
		keep[u.Path] = true
	}
	var gonePaths, goneUnits []string
	for _, u := range before.Units {
		if !keep[u.Path] {
			gonePaths = append(gonePaths, u.Path)
			goneUnits = append(goneUnits, u.systemdName())
		}
	}
	if len(gonePaths) > 0 {
		if err := m.host.Stop(ctx, p.Name, goneUnits); err != nil {
			return fail("remove", err)
		}
		if err := m.host.DeleteUnits(ctx, p.Name, gonePaths); err != nil {
			return fail("remove", err)
		}
	}
	if err := m.host.Commit(ctx, p.Name, commit); err != nil {
		return fail("files", err)
	}

	// A service a person stopped stays stopped, and so does every service
	// that needs one: started, it would start what was stopped.
	stopped := map[string]bool{}
	for _, s := range svc.Stopped {
		if _, ok := (Applied{Units: next}).unit(s); ok {
			stopped[s] = true
			for _, d := range dependants(next, s) {
				stopped[d] = true
			}
		}
	}
	svc.Stopped = keys(stopped)
	if err := m.store.SetStopped(ctx, p.Name, svc.Stopped); err != nil {
		return fail("units", err)
	}
	if err := m.host.Install(ctx, Unit{Name: p.Name, Files: unitFiles(next, svc.Stopped)}); err != nil {
		return fail("units", err)
	}

	// Changed is measured against what was applied, never against the disk:
	// after a failure the disk already holds the new files.
	var again, fresh []string
	for _, u := range next {
		if u.Kind != KindContainer || stopped[u.Service] {
			continue
		}
		old, ok := svc.Applied.unit(u.Service)
		switch {
		case !ok:
			fresh = append(fresh, u.Service)
		case old.Body != u.Body || old.EnvSHA != u.EnvSHA || !sameInputs(old, u, svc.Applied.Manifest, rev.manifest):
			again = append(again, u.Service)
		default:
			fresh = append(fresh, u.Service) // a start of what runs changes nothing
		}
	}
	if len(again) > 0 {
		if err := m.host.Restart(ctx, p.Name, systemdNames(next, again)); err != nil {
			return fail("start", err)
		}
	}
	if len(fresh) > 0 {
		if err := m.host.Start(ctx, p.Name, systemdNames(next, fresh)); err != nil {
			return fail("start", err)
		}
	}
	applied := plan
	if err := m.store.SetApplied(ctx, p.Name, applied); err != nil {
		return fail("record", err)
	}
	svc.Applied, svc.Pending, svc.State = applied, nil, Deployed
	m.working(p.Name, false)
	return m.view(ctx, svc), nil
}

// reason is the last part of a host error, which says what went wrong: "Error:
// …" of a tool, or the error itself.
func reason(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, "Error: "); i >= 0 {
		s = s[i+len("Error: "):]
	}
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160])
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// sameInputs reports whether the managed files a unit reads are the same in
// both manifests.
func sameInputs(old, now UnitFile, was, is Manifest) bool {
	if strings.Join(old.Inputs, "\x00") != strings.Join(now.Inputs, "\x00") {
		return false
	}
	for _, p := range now.Inputs {
		if !was.sameUnder(is, p) {
			return false
		}
	}
	return true
}

// pull asks the registry what each image's reference points to now. It is
// the one verb that moves a tag.
func (m *Module) pull(ctx context.Context, r Ref) (View, error) {
	defer m.lock(r.Name)()
	svc, err := m.applied(ctx, r)
	if err != nil {
		return View{}, err
	}
	if svc.Pending != nil {
		// Its units are not all as the record says: an apply finishes it first.
		return View{}, with(ErrNotApplied, "an apply did not finish")
	}
	stopped := map[string]bool{}
	for _, s := range svc.Stopped {
		stopped[s] = true
	}
	var changed []string
	units := append([]UnitFile{}, svc.Applied.Units...)
	for i, u := range units {
		if u.Kind != KindContainer || (r.Service != "" && r.Service != u.Service) {
			continue
		}
		d, err := m.host.Pull(ctx, svc.Name, u.Image)
		if err != nil {
			return View{}, fmt.Errorf("services: pulling for %s: %w", svc.Name, err)
		}
		if d == u.Digest {
			continue
		}
		units[i].Body = strings.Replace(u.Body, "@"+u.Digest+"\n", "@"+d+"\n", 1)
		units[i].Digest = d
		if !stopped[u.Service] {
			changed = append(changed, u.Service)
		}
	}
	svc.Applied.Units = units
	// The units first, then the record: a failure between the two leaves the
	// record naming the old digest, and the next apply writes the old units back.
	if err := m.host.Install(ctx, Unit{Name: svc.Name, Files: unitFiles(units, svc.Stopped)}); err != nil {
		return View{}, fmt.Errorf("services: writing the units of %s: %w", svc.Name, err)
	}
	if err := m.store.SetApplied(ctx, svc.Name, svc.Applied); err != nil {
		return View{}, err
	}
	if len(changed) > 0 {
		if err := m.host.Restart(ctx, svc.Name, systemdNames(units, changed)); err != nil {
			return View{}, fmt.Errorf("services: restarting %s: %w", svc.Name, err)
		}
	}
	return m.view(ctx, svc), nil
}
