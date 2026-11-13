package services

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// THE COMPOSE SUBSET. The core reads the file itself. A key outside the
// subset is refused by its name, never dropped: what the review shows is all
// that the file says.

// Severities of a Finding.
const (
	Refused = "refused" // stops the apply
	Warning = "warning" // shown, and confirmed with the review
)

// Finding is one thing a stack's review says. Detail never holds a value that
// came from .env: it names the key.
type Finding struct {
	ID       string `json:"id"`       // constant: the panel's message id
	Severity string `json:"severity"` // Refused or Warning
	Service  string `json:"service"`  // "" for the stack
	Detail   string `json:"detail"`   // the key or the value, cut short
}

// Stack is a compose file's subset, parsed.
type Stack struct {
	Services []Spec   // by name
	Volumes  []string // named volumes, by name
}

// Spec is one container.
type Spec struct {
	Name        string
	Image       string // as written, made fully qualified
	Command     []string
	Entrypoint  []string
	Environment []EnvVar // by key
	EnvFile     []string // paths inside the stack's folder
	Ports       []Publish
	Volumes     []Mount
	HostNetwork bool
	DependsOn   []string
	Restart     string // "no", "always", "on-failure", "unless-stopped"
	HasUser     bool
	UID, GID    int
	ReadOnly    bool
	CapAdd      []string
	CapDrop     []string
	Tmpfs       []string
	WorkingDir  string
	Hostname    string
	MemLimit    int64 // bytes; 0 for none
	Health      *Health
}

// EnvVar is one variable of a container's environment.
type EnvVar struct {
	Key, Value string
	// FromEnv marks a value filled from .env: it goes to the container through
	// a file, never through a command line.
	FromEnv bool
}

// Publish is one "ports" entry.
type Publish struct {
	Addr             netip.Addr // the zero Addr for every address
	HostFrom, HostTo int
	ContFrom, ContTo int
	Proto            string // "tcp" or "udp"
}

// Use is the host ports p claims.
func (p Publish) Use() PortUse { return PortUse{Proto: p.Proto, From: p.HostFrom, To: p.HostTo} }

// Public reports whether p is reachable from another machine, the firewall
// allowing.
func (p Publish) Public() bool { return !p.Addr.IsValid() || !p.Addr.IsLoopback() }

// Mount is one "volumes" entry.
type Mount struct {
	Source   string // a clean path inside the stack's folder, or a named volume
	Named    bool
	Target   string
	ReadOnly bool
}

// Health is a container's health check.
type Health struct {
	Kind        string   // "exec", "shell" or "none"
	Args        []string // for exec
	Shell       string   // for shell
	Interval    string
	Timeout     string
	StartPeriod string
	Retries     int
}

// MaxRange bounds a port range: a relay needs hundreds of ports, never tens
// of thousands.
const MaxRange = 4096

// maxServices bounds a stack.
const maxServices = 32

type parser struct {
	env      map[string]string
	findings []Finding
	// fromEnv is set by str when the last value it read was filled from .env.
	fromEnv bool
}

func (p *parser) warn(id, service, detail string) {
	p.findings = append(p.findings, Finding{ID: id, Severity: Warning, Service: service, Detail: short(detail)})
}

func (p *parser) refuse(id, service, detail string) {
	p.findings = append(p.findings, Finding{ID: id, Severity: Refused, Service: service, Detail: short(detail)})
}

// short keeps a detail printable and brief.
func short(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

// Parse reads a compose file against the subset. env is the folder's .env,
// which fills ${KEY} in the file; the core's own environment never does.
func Parse(data []byte, env map[string]string) (Stack, []Finding) {
	p := &parser{env: env}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		p.refuse("bad-yaml", "", firstLineOf(err.Error()))
		return Stack{}, p.findings
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		p.refuse("bad-yaml", "", "the file is not a mapping")
		return Stack{}, p.findings
	}
	var st Stack
	var services *yaml.Node
	declared := map[string]bool{}
	p.each(doc.Content[0], "", "", func(key string, v *yaml.Node) {
		switch key {
		case "name", "version": // the stack's name is its folder's; the version is not read
		case "services":
			services = v
		case "volumes":
			p.each(v, "", "volumes", func(name string, opts *yaml.Node) {
				switch {
				case !ValidName(name):
					p.refuse("bad-volume-name", "", name)
				case !empty(opts):
					p.refuse("unsupported-key", "", "volumes."+name+": a named volume takes no options")
				default:
					declared[name] = true
					st.Volumes = append(st.Volumes, name)
				}
			})
		default:
			p.refuse("unsupported-key", "", key)
		}
	})
	sort.Strings(st.Volumes)
	if services == nil {
		p.refuse("no-services", "", "")
		return st, p.findings
	}
	p.each(services, "", "services", func(name string, v *yaml.Node) {
		if !ValidName(name) {
			p.refuse("bad-service-name", "", name)
			return
		}
		st.Services = append(st.Services, p.spec(name, v, declared))
	})
	sort.Slice(st.Services, func(i, j int) bool { return st.Services[i].Name < st.Services[j].Name })
	switch n := len(st.Services); {
	case n == 0:
		p.refuse("no-services", "", "")
	case n > maxServices:
		p.refuse("too-many-services", "", strconv.Itoa(n))
	}
	return st, p.findings
}

func firstLineOf(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// empty reports whether n is null, or a mapping or sequence with nothing in it.
func empty(n *yaml.Node) bool {
	return n == nil || n.Tag == "!!null" || ((n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && len(n.Content) == 0)
}

// each calls fn for every key of the mapping n. Anything else than a mapping,
// a key that is not a plain string, and a key said twice are refused.
func (p *parser) each(n *yaml.Node, service, where string, fn func(key string, v *yaml.Node)) {
	if n.Kind != yaml.MappingNode {
		p.refuse("bad-value", service, where+": a mapping is expected")
		return
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" {
			p.refuse("bad-value", service, where+": a key is not a plain string")
			continue
		}
		if seen[k.Value] {
			p.refuse("bad-value", service, where+"."+k.Value+": said twice")
			continue
		}
		seen[k.Value] = true
		fn(k.Value, v)
	}
}

// str is a scalar's text, with ${KEY} filled from .env. ok is false, and a
// finding is added, for anything else than a scalar, for a variable .env does
// not have, and for a value no unit file may hold.
func (p *parser) str(n *yaml.Node, service, where string) (string, bool) {
	p.fromEnv = false
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		p.refuse("bad-value", service, where+": a value is expected")
		return "", false
	}
	s, used, missing := interpolate(n.Value, p.env)
	if missing != "" {
		p.refuse("unset-variable", service, where+": ${"+missing+"} is not in .env")
		return "", false
	}
	if strings.ContainsAny(s, "\n\r\x00") {
		p.refuse("unit-text", service, where+": a line break or a NUL")
		return "", false
	}
	p.fromEnv = used
	return s, true
}

// list is a sequence of scalars, or one scalar.
func (p *parser) list(n *yaml.Node, service, where string) []string {
	if n.Kind == yaml.ScalarNode {
		if s, ok := p.str(n, service, where); ok {
			return []string{s}
		}
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		p.refuse("bad-value", service, where+": a list is expected")
		return nil
	}
	var out []string
	for _, c := range n.Content {
		if s, ok := p.str(c, service, where); ok {
			out = append(out, s)
		}
	}
	return out
}

var varRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// named is what a variable that could not be read is called in a finding: its
// own text, or "?" when it has none.
func named(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// interpolate fills $KEY, ${KEY}, ${KEY:-default} and ${KEY-default} from env;
// "$$" is a dollar sign. used says a variable was filled; missing names the
// first variable env does not have and the value gives no default for.
func interpolate(s string, env map[string]string) (out string, used bool, missing string) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		rest := s[i+1:]
		switch {
		case rest[0] == '$':
			b.WriteByte('$')
			i++
		case rest[0] == '{':
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return "", false, named(strings.TrimPrefix(rest, "{"))
			}
			body := rest[1:end]
			key := varRE.FindString(body)
			if key == "" {
				return "", false, named(body)
			}
			def, hasDef, unsetOnly := "", false, false
			switch tail := body[len(key):]; {
			case tail == "":
			case strings.HasPrefix(tail, ":-"):
				def, hasDef = tail[2:], true
			case strings.HasPrefix(tail, "-"):
				def, hasDef, unsetOnly = tail[1:], true, true
			default:
				return "", false, named(body)
			}
			v, ok := env[key]
			switch {
			case ok && (v != "" || unsetOnly || !hasDef):
				b.WriteString(v)
				used = true
			case hasDef:
				b.WriteString(def)
			default:
				return "", false, key
			}
			i += end + 1
		default:
			key := varRE.FindString(rest)
			if key == "" {
				b.WriteByte('$')
				continue
			}
			v, ok := env[key]
			if !ok {
				return "", false, key
			}
			b.WriteString(v)
			used = true
			i += len(key)
		}
	}
	return b.String(), used, ""
}

var (
	envKeyRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	capRE      = regexp.MustCompile(`^[A-Z][A-Z_]{1,30}$`)
	durationRE = regexp.MustCompile(`^([0-9]+(ms|s|m|h))+$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tmpfsRE    = regexp.MustCompile(`^/[A-Za-z0-9._/-]*(:[a-z0-9=,]+)?$`)
	absPathRE  = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)
	relPathRE  = regexp.MustCompile(`^[A-Za-z0-9._/@+-]+$`)
)

// ParseEnv reads a .env file: KEY=value lines, "#" comments, a value in one
// pair of quotes having them removed. bad lists the lines it could not read,
// by number: a line's text may be a secret.
func ParseEnv(data []byte) (env map[string]string, bad []int) {
	env = map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKeyRE.MatchString(k) || strings.ContainsRune(v, 0) {
			bad = append(bad, i+1)
			continue
		}
		v = strings.TrimSpace(v)
		if n := len(v); n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n-1] == v[0] {
			v = v[1 : n-1]
		}
		env[k] = v
	}
	return env, bad
}

// spec reads one service.
func (p *parser) spec(name string, n *yaml.Node, volumes map[string]bool) Spec {
	s := Spec{Name: name, Restart: "no"}
	at := func(key string) string { return "services." + name + "." + key }
	var hostPorts *yaml.Node
	p.each(n, name, "services."+name, func(key string, v *yaml.Node) {
		w := at(key)
		switch key {
		case "image":
			if img, ok := p.str(v, name, w); ok {
				s.Image = p.image(name, img)
			}
		case "command":
			s.Command = p.words(v, name, w)
		case "entrypoint":
			s.Entrypoint = p.words(v, name, w)
		case "environment":
			s.Environment = p.environment(v, name, w)
		case "env_file":
			for _, f := range p.list(v, name, w) {
				if c, ok := p.inside(name, w, f); ok {
					s.EnvFile = append(s.EnvFile, c)
				}
			}
		case "ports":
			hostPorts = v
		case "volumes":
			if v.Kind != yaml.SequenceNode {
				p.refuse("bad-value", name, w+": a list is expected")
				return
			}
			for _, c := range v.Content {
				if c.Kind != yaml.ScalarNode {
					p.refuse("unsupported-key", name, w+": the long form")
					continue
				}
				if raw, ok := p.str(c, name, w); ok {
					if m, ok := p.mount(name, raw, volumes); ok {
						s.Volumes = append(s.Volumes, m)
					}
				}
			}
		case "network_mode":
			if mode, ok := p.str(v, name, w); ok {
				if mode != "host" {
					p.refuse("unsupported-value", name, w+": only \"host\"")
				}
				s.HostNetwork = mode == "host"
			}
		case "depends_on":
			s.DependsOn = p.depends(v, name, w)
		case "restart":
			if r, ok := p.str(v, name, w); ok {
				switch r {
				case "no", "always", "on-failure", "unless-stopped":
					s.Restart = r
				default:
					p.refuse("unsupported-value", name, w+": no, always, on-failure or unless-stopped")
				}
			}
		case "user":
			if u, ok := p.str(v, name, w); ok {
				a, b, cut := strings.Cut(u, ":")
				uid, err1 := strconv.Atoi(a)
				gid, err2 := strconv.Atoi(b)
				if !cut || err1 != nil || err2 != nil || uid < 0 || gid < 0 || uid > 65535 || gid > 65535 {
					p.refuse("user-not-numeric", name, w+": two numbers, as \"991:991\"")
					return
				}
				s.HasUser, s.UID, s.GID = true, uid, gid
			}
		case "read_only":
			s.ReadOnly = p.boolean(v, name, w)
		case "cap_add":
			s.CapAdd = p.caps(v, name, w)
		case "cap_drop":
			s.CapDrop = p.caps(v, name, w)
		case "tmpfs":
			for _, t := range p.list(v, name, w) {
				if !tmpfsRE.MatchString(t) {
					p.refuse("bad-value", name, w+": "+t)
					continue
				}
				s.Tmpfs = append(s.Tmpfs, t)
			}
		case "working_dir":
			if d, ok := p.str(v, name, w); ok {
				if !absPathRE.MatchString(d) {
					p.refuse("bad-value", name, w+": an absolute path")
					return
				}
				s.WorkingDir = d
			}
		case "hostname":
			if h, ok := p.str(v, name, w); ok {
				if !hostRE.MatchString(h) {
					p.refuse("bad-value", name, w+": a host name's one label")
					return
				}
				s.Hostname = h
			}
		case "mem_limit":
			if m, ok := p.str(v, name, w); ok {
				b, ok := parseSize(m)
				if !ok {
					p.refuse("bad-value", name, w+": a size, as 512m")
					return
				}
				s.MemLimit = b
			}
		case "healthcheck":
			s.Health = p.health(v, name, w)
		case "labels":
			if v.Kind != yaml.MappingNode && v.Kind != yaml.SequenceNode {
				p.refuse("bad-value", name, w)
			}
		case "container_name":
			_, _ = p.str(v, name, w) // read and dropped: the name is <stack>-<service>
		default:
			p.refuse("unsupported-key", name, w)
		}
	})
	if s.Image == "" {
		p.refuse("no-image", name, "")
	}
	if hostPorts != nil {
		s.Ports = p.ports(hostPorts, name, at("ports"), s.HostNetwork)
	}
	return s
}

// image makes an image's name fully qualified, the way Docker reads a short
// one: Podman is asked for exactly one name, and guesses no registry.
func (p *parser) image(service, img string) string {
	if !imageRE.MatchString(img) {
		p.refuse("bad-value", service, "image: "+img)
		return ""
	}
	first, _, slash := strings.Cut(img, "/")
	switch {
	case !slash:
		return "docker.io/library/" + img
	case !strings.ContainsAny(first, ".:") && first != "localhost":
		return "docker.io/" + img
	}
	return img
}

var imageRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/:-]*[a-z0-9])?(@sha256:[0-9a-f]{64})?$`)

// ImageRef splits a fully qualified image into its repository and what picks
// the image in it: ":tag" or "@sha256:…". An image with neither is ":latest".
func ImageRef(img string) (repo, pick string) {
	if i := strings.Index(img, "@"); i >= 0 {
		return strings.TrimSuffix(img[:i], tagOf(img[:i])), img[i:]
	}
	if t := tagOf(img); t != "" {
		return strings.TrimSuffix(img, t), t
	}
	return img, ":latest"
}

// tagOf is img's ":tag", or "": a colon before the last slash is a port.
func tagOf(img string) string {
	i := strings.LastIndex(img, ":")
	if i < 0 || strings.Contains(img[i:], "/") {
		return ""
	}
	return img[i:]
}

// words is a command: a list as it is, or a string split the way a shell
// splits words, with no expansion.
func (p *parser) words(n *yaml.Node, service, where string) []string {
	if empty(n) {
		return nil
	}
	// A value of .env in a command is on the container's command line, which
	// every user of the host can read: an environment variable is not.
	if n.Kind == yaml.SequenceNode {
		var out []string
		fromEnv := false
		for _, c := range n.Content {
			if s, ok := p.str(c, service, where); ok {
				out = append(out, s)
				fromEnv = fromEnv || p.fromEnv
			}
		}
		if fromEnv {
			p.warn("env-in-command", service, where)
		}
		return out
	}
	s, ok := p.str(n, service, where)
	if !ok {
		return nil
	}
	if p.fromEnv {
		p.warn("env-in-command", service, where)
	}
	out, ok := split(s)
	if !ok {
		p.refuse("bad-value", service, where+": a quote is not closed")
		return nil
	}
	return out
}

// split cuts s into words at white space; quotes group, and a backslash takes
// the next character as it is (inside single quotes it is a backslash).
func split(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote, in = c, true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if in {
		out = append(out, cur.String())
	}
	return out, true
}

func (p *parser) boolean(n *yaml.Node, service, where string) bool {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		p.refuse("bad-value", service, where+": true or false")
		return false
	}
	return n.Value == "true"
}

func (p *parser) environment(n *yaml.Node, service, where string) []EnvVar {
	var out []EnvVar
	add := func(k, v string, fromEnv bool) {
		if !envKeyRE.MatchString(k) {
			p.refuse("bad-value", service, where+": a variable's name")
			return
		}
		out = append(out, EnvVar{Key: k, Value: v, FromEnv: fromEnv})
	}
	switch n.Kind {
	case yaml.MappingNode:
		p.each(n, service, where, func(k string, v *yaml.Node) {
			if v.Tag == "!!null" {
				// Compose would pass the variable through from its own
				// environment; the core's is never a stack's.
				p.refuse("env-no-value", service, where+"."+k)
				return
			}
			if s, ok := p.str(v, service, where+"."+k); ok {
				add(k, s, p.fromEnv)
			}
		})
	case yaml.SequenceNode:
		for _, c := range n.Content {
			s, ok := p.str(c, service, where)
			if !ok {
				continue
			}
			fromEnv := p.fromEnv
			k, v, cut := strings.Cut(s, "=")
			if !cut {
				p.refuse("env-no-value", service, where+"."+short(k))
				continue
			}
			add(k, v, fromEnv)
		}
	default:
		p.refuse("bad-value", service, where+": a mapping or a list")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	for i := 1; i < len(out); i++ {
		if out[i].Key == out[i-1].Key {
			p.refuse("bad-value", service, where+"."+out[i].Key+": said twice")
		}
	}
	return out
}

// inside is a path of the compose file, made clean, when it stays inside the
// stack's folder and outside the core's own part of it.
func (p *parser) inside(service, where, raw string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "/"):
		p.refuse("absolute-path", service, where+": "+raw)
		return "", false
	case !relPathRE.MatchString(raw):
		p.refuse("bad-value", service, where+": "+raw)
		return "", false
	}
	c := path.Clean(raw)
	switch {
	case c == ".." || strings.HasPrefix(c, "../"):
		p.refuse("path-leaves-folder", service, where+": "+raw)
		return "", false
	case c == ".":
		p.refuse("whole-folder", service, where)
		return "", false
	case c == Generated || strings.HasPrefix(c, Generated+"/"):
		p.refuse("reserved-path", service, where+": "+raw)
		return "", false
	}
	return c, true
}

// Generated is the folder of a stack's files the core writes itself. It is
// never data, never in a manifest, and never a mount's source.
const Generated = ".autopanel"

func (p *parser) mount(service, raw string, volumes map[string]bool) (Mount, bool) {
	where := "services." + service + ".volumes"
	parts := strings.Split(raw, ":")
	if len(parts) < 2 || len(parts) > 3 {
		p.refuse("unsupported-value", service, where+": source:target[:ro]")
		return Mount{}, false
	}
	m := Mount{Target: parts[1]}
	if len(parts) == 3 {
		switch parts[2] {
		case "ro":
			m.ReadOnly = true
		case "rw":
		default:
			p.refuse("unsupported-value", service, where+": only ro or rw after the target")
			return Mount{}, false
		}
	}
	if !absPathRE.MatchString(m.Target) || path.Clean(m.Target) != m.Target || m.Target == "/" {
		p.refuse("bad-value", service, where+": the target is an absolute path")
		return Mount{}, false
	}
	src := parts[0]
	if !strings.Contains(src, "/") && src != "." && src != ".." {
		// A bare word is a named volume.
		if !volumes[src] {
			p.refuse("undeclared-volume", service, where+": "+src)
			return Mount{}, false
		}
		m.Source, m.Named = src, true
		return m, true
	}
	c, ok := p.inside(service, where, src)
	if !ok {
		return Mount{}, false
	}
	m.Source = c
	return m, true
}

func (p *parser) depends(n *yaml.Node, service, where string) []string {
	var out []string
	switch n.Kind {
	case yaml.SequenceNode:
		out = p.list(n, service, where)
	case yaml.MappingNode:
		p.each(n, service, where, func(dep string, v *yaml.Node) {
			ok := true
			if !empty(v) {
				p.each(v, service, where+"."+dep, func(k string, c *yaml.Node) {
					// A weaker contract is never put in a stronger one's place.
					if k != "condition" || c.Kind != yaml.ScalarNode || c.Value != "service_started" {
						p.refuse("unsupported-dependency", service, where+"."+dep+"."+k+": "+short(c.Value))
						ok = false
					}
				})
			}
			if ok {
				out = append(out, dep)
			}
		})
	default:
		p.refuse("bad-value", service, where+": a list or a mapping")
	}
	sort.Strings(out)
	return out
}

func (p *parser) caps(n *yaml.Node, service, where string) []string {
	var out []string
	for _, c := range p.list(n, service, where) {
		c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if !capRE.MatchString(c) {
			p.refuse("bad-value", service, where)
			continue
		}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// parseSize reads "512m", "1g", "2048k", "1073741824" as bytes.
func parseSize(s string) (int64, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "b")
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "g"):
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<40)/mult {
		return 0, false
	}
	return n * mult, true
}

func (p *parser) health(n *yaml.Node, service, where string) *Health {
	h := &Health{}
	disabled := false
	p.each(n, service, where, func(k string, v *yaml.Node) {
		w := where + "." + k
		switch k {
		case "test":
			if v.Kind == yaml.ScalarNode {
				if s, ok := p.str(v, service, w); ok && s != "" {
					h.Kind, h.Shell = "shell", s
				}
				return
			}
			t := p.list(v, service, w)
			switch {
			case len(t) == 1 && t[0] == "NONE":
				h.Kind = "none"
			case len(t) == 2 && t[0] == "CMD-SHELL":
				h.Kind, h.Shell = "shell", t[1]
			case len(t) >= 2 && t[0] == "CMD":
				h.Kind, h.Args = "exec", t[1:]
			default:
				p.refuse("bad-value", service, w+": [\"CMD\", …], [\"CMD-SHELL\", …] or [\"NONE\"]")
			}
		case "interval", "timeout", "start_period":
			d, ok := p.str(v, service, w)
			if !ok {
				return
			}
			if !durationRE.MatchString(d) {
				p.refuse("bad-value", service, w+": a duration, as 30s")
				return
			}
			switch k {
			case "interval":
				h.Interval = d
			case "timeout":
				h.Timeout = d
			default:
				h.StartPeriod = d
			}
		case "retries":
			s, ok := p.str(v, service, w)
			r, err := strconv.Atoi(s)
			if !ok || err != nil || r < 1 || r > 100 {
				p.refuse("bad-value", service, w+": a number from 1 to 100")
				return
			}
			h.Retries = r
		case "disable":
			disabled = p.boolean(v, service, w)
		default:
			p.refuse("unsupported-key", service, w)
		}
	})
	if disabled {
		return &Health{Kind: "none"}
	}
	if h.Kind == "" {
		p.refuse("bad-value", service, where+": no test")
		return nil
	}
	return h
}

// ports reads "ports". Under the host's network nothing is published: there
// an entry declares a port the service listens on, so its two numbers are one
// and it names no address.
func (p *parser) ports(n *yaml.Node, service, where string, hostNetwork bool) []Publish {
	if n.Kind != yaml.SequenceNode {
		p.refuse("bad-value", service, where+": a list is expected")
		return nil
	}
	var out []Publish
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			p.refuse("unsupported-key", service, where+": the long form")
			continue
		}
		raw, ok := p.str(c, service, where)
		if !ok {
			continue
		}
		pub, why := parsePublish(raw)
		if why != "" {
			p.refuse("bad-port", service, where+": "+raw+": "+why)
			continue
		}
		if hostNetwork && (pub.Addr.IsValid() || pub.HostFrom != pub.ContFrom) {
			p.refuse("host-network-port", service, where+": "+raw)
			continue
		}
		out = append(out, pub)
	}
	return out
}

// parsePublish reads "[address:]host:container[/proto]", each port a number
// or a range.
func parsePublish(raw string) (Publish, string) {
	pub := Publish{Proto: "tcp"}
	rest, proto, cut := strings.Cut(raw, "/")
	if cut {
		if proto != "tcp" && proto != "udp" {
			return pub, "tcp or udp"
		}
		pub.Proto = proto
	}
	// The address may be an IPv6 one in brackets, with colons of its own.
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]:")
		if end < 0 {
			return pub, "an address in brackets is followed by its ports"
		}
		a, err := netip.ParseAddr(rest[1:end])
		if err != nil {
			return pub, "not an address"
		}
		pub.Addr, rest = a, rest[end+2:]
	}
	parts := strings.Split(rest, ":")
	if len(parts) == 3 && !pub.Addr.IsValid() {
		a, err := netip.ParseAddr(parts[0])
		if err != nil {
			return pub, "not an address"
		}
		pub.Addr, parts = a, parts[1:]
	}
	if len(parts) != 2 {
		return pub, "name the host's port and the container's"
	}
	var ok1, ok2 bool
	pub.HostFrom, pub.HostTo, ok1 = portRange(parts[0])
	pub.ContFrom, pub.ContTo, ok2 = portRange(parts[1])
	switch {
	case !ok1 || !ok2:
		return pub, "a port is a number from 1 to 65535, or first-last"
	case pub.HostTo-pub.HostFrom != pub.ContTo-pub.ContFrom:
		return pub, "the two ranges differ in size"
	case pub.HostTo-pub.HostFrom+1 > MaxRange:
		return pub, fmt.Sprintf("a range holds at most %d ports", MaxRange)
	}
	return pub, ""
}

func portRange(s string) (from, to int, ok bool) {
	a, b, cut := strings.Cut(s, "-")
	from, ok = onePort(a)
	to = from
	if cut {
		var ok2 bool
		to, ok2 = onePort(b)
		ok = ok && ok2 && from <= to
	}
	return from, to, ok
}

func onePort(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}
