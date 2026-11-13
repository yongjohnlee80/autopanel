package services

import (
	"sort"
	"strconv"
	"strings"
)

// THE POLICY. What a stack may not do is refused before anything is written;
// what it may do but an administrator should see is a warning in the review.

// defaultCaps are the capabilities a rootless Podman container has unless its
// file drops them. A stack may add back only these: each is held inside the
// stack user's own user namespace. The list is the code's own, so a host that
// widened its Podman defaults does not widen a stack's.
var defaultCaps = map[string]bool{
	"CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true, "KILL": true, "NET_BIND_SERVICE": true,
	"SETFCAP": true, "SETGID": true, "SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
}

// Claim is a port another stack has.
type Claim struct {
	Stack string
	PortUse
}

// Facts are what a check reads beside the file: the host's state and what the
// stack was before.
type Facts struct {
	Taken     []Claim   // the ports of the other stacks, applied or being applied
	Listening []PortUse // the listening sockets that are not this stack's own
	// Data and Managed are the stack's paths as they were last applied, and as
	// an apply that did not finish may have left them.
	Data    []string
	Managed []string
	// Present are the managed paths of the new file that are under the stack's
	// own folder already.
	Present map[string]bool
	// Links are the paths of the new file that are, or pass through, a
	// symbolic link.
	Links []string
}

// managedPaths are the files of a stack that an apply replaces: every
// env_file, and the source of every read-only mount.
func managedPaths(st Stack) []string {
	set := map[string]bool{}
	for _, s := range st.Services {
		for _, p := range inputs(s) {
			set[p] = true
		}
	}
	return keys(set)
}

// dataPaths are the sources of a stack's writable mounts: made once, and
// never written by the core again.
func dataPaths(st Stack) []string {
	set := map[string]bool{}
	for _, s := range st.Services {
		for _, m := range s.Volumes {
			if !m.Named && !m.ReadOnly {
				set[m.Source] = true
			}
		}
	}
	return keys(set)
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// within reports whether a is b, or inside it.
func within(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") }

// touches reports whether one path is the other, or holds it.
func touches(a, b string) bool { return within(a, b) || within(b, a) }

// claims are the host ports a stack's file asks for.
func claims(st Stack) []PortUse {
	var out []PortUse
	for _, s := range st.Services {
		for _, p := range s.Ports {
			out = append(out, p.Use())
		}
	}
	return out
}

func portText(p PortUse) string {
	if p.From == p.To {
		return strconv.Itoa(p.From) + "/" + p.Proto
	}
	return strconv.Itoa(p.From) + "-" + strconv.Itoa(p.To) + "/" + p.Proto
}

// check reads a parsed stack against the policy and the facts.
func check(st Stack, f Facts) []Finding {
	var out []Finding
	refuse := func(id, service, detail string) {
		out = append(out, Finding{ID: id, Severity: Refused, Service: service, Detail: short(detail)})
	}
	warn := func(id, service, detail string) {
		out = append(out, Finding{ID: id, Severity: Warning, Service: service, Detail: short(detail)})
	}

	names := map[string]bool{}
	for _, s := range st.Services {
		names[s.Name] = true
	}
	// Two units of one stack may not become one systemd service.
	if needsNetwork(st) && names["network"] {
		refuse("unit-name-taken", "network", "the stack's network has this name")
	}
	for _, v := range st.Volumes {
		if names[v+"-volume"] {
			refuse("unit-name-taken", v+"-volume", "the volume "+v+" has this name")
		}
	}

	// Data stays data: a path that was data, or that is in the stack's folder
	// and was not put there by an apply, is never made a managed file.
	managed, data := managedPaths(st), dataPaths(st)
	for _, m := range managed {
		for _, d := range data {
			if touches(m, d) {
				refuse("data-overlap", "", m+" is mounted read-only and "+d+" writable")
			}
		}
		for _, d := range f.Data {
			if touches(m, d) {
				refuse("data-overlap", "", m+" would replace the stack's data in "+d)
			}
		}
		if f.Present[m] && !covered(m, f.Managed) {
			refuse("data-overlap", "", m+" is in the stack's folder already, and no apply put it there")
		}
	}
	for _, l := range f.Links {
		refuse("symlink", "", l)
	}

	var all []PortUse
	for _, s := range st.Services {
		for _, c := range s.CapAdd {
			if !defaultCaps[c] {
				refuse("capability", s.Name, c)
			}
		}
		for _, d := range s.DependsOn {
			if !names[d] || d == s.Name {
				refuse("unknown-dependency", s.Name, d)
			}
		}
		if h := s.Health; h != nil {
			switch {
			case h.Kind == "exec" && reservedHealthWord(h.Args[0]):
				refuse("bad-value", s.Name, "healthcheck.test: its command is named "+h.Args[0])
			case h.Kind == "shell" && strings.HasPrefix(strings.TrimSpace(h.Shell), "["):
				refuse("bad-value", s.Name, "healthcheck.test: a shell command that starts with [")
			}
		}
		for _, p := range s.Ports {
			u := p.Use()
			switch {
			case u.From < 1024:
				// The stack's user cannot bind it, and web traffic goes through
				// the gate.
				refuse("privileged-port", s.Name, portText(u))
				continue
			}
			for _, o := range all {
				if u.overlaps(o) {
					refuse("port-twice", s.Name, portText(u))
				}
			}
			all = append(all, u)
			for _, c := range f.Taken {
				if u.overlaps(c.PortUse) {
					refuse("port-taken", s.Name, portText(u)+" is stack "+c.Stack+"'s")
				}
			}
			// One finding per port, however many sockets hold it (one per
			// address and protocol family).
			for _, l := range f.Listening {
				if u.overlaps(l) {
					refuse("port-in-use", s.Name, portText(u))
					break
				}
			}
			if p.Public() || s.HostNetwork {
				warn("public-port", s.Name, portText(u))
			}
		}

		if _, pick := ImageRef(s.Image); !strings.HasPrefix(pick, "@") {
			warn("image-by-tag", s.Name, s.Image)
		}
		if s.HostNetwork {
			warn("host-network", s.Name, "")
			if len(s.Ports) == 0 {
				warn("host-network-no-ports", s.Name, "")
			}
		}
		if s.MemLimit == 0 {
			warn("no-memory-limit", s.Name, "")
		}
		if !s.ReadOnly {
			warn("writable-root", s.Name, "")
		}
		if !s.HasUser {
			warn("image-user", s.Name, "")
		}
		if len(s.CapAdd) > 0 {
			warn("capability-added", s.Name, strings.Join(s.CapAdd, ", "))
		}
	}
	for _, c := range cycles(st) {
		refuse("dependency-cycle", c, "")
	}
	// Said of every stack: its private network keeps other stacks out of it,
	// not it out of what the host publishes.
	warn("reach", "", "")
	return out
}

// covered reports whether p is one of paths, or inside one.
func covered(p string, paths []string) bool {
	for _, m := range paths {
		if within(p, m) {
			return true
		}
	}
	return false
}

// reservedHealthWord is a first word Podman would read as a kind of check.
func reservedHealthWord(s string) bool {
	switch strings.ToUpper(s) {
	case "CMD", "CMD-SHELL", "NONE":
		return true
	}
	return false
}

// cycles names the services that depend on themselves through others.
func cycles(st Stack) []string {
	deps := map[string][]string{}
	for _, s := range st.Services {
		deps[s.Name] = s.DependsOn
	}
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var bad []string
	var visit func(n string)
	visit = func(n string) {
		state[n] = visiting
		for _, d := range deps[n] {
			switch state[d] {
			case visiting:
				bad = append(bad, n)
			case 0:
				if _, ok := deps[d]; ok {
					visit(d)
				}
			}
		}
		state[n] = done
	}
	for _, s := range st.Services {
		if state[s.Name] == 0 {
			visit(s.Name)
		}
	}
	sort.Strings(bad)
	return bad
}

// refused reports whether any finding stops an apply.
func refused(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Refused {
			return true
		}
	}
	return false
}

// dependants are the services that need name, through any number of others.
func dependants(units []UnitFile, name string) []string {
	set := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, u := range units {
			if u.Kind != KindContainer || set[u.Service] || u.Service == name {
				continue
			}
			for _, n := range u.Needs {
				if n == name || set[n] {
					set[u.Service], changed = true, true
					break
				}
			}
		}
	}
	return keys(set)
}
