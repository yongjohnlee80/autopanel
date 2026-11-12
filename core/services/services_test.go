package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestATemplateValidatesItsOptions(t *testing.T) {
	v, err := TURN.Validate(map[string]string{"realm": "Turn.Example.com."})
	if err != nil {
		t.Fatal(err)
	}
	if v.Get("realm") != "turn.example.com" || v.Port("port") != 3478 {
		t.Fatalf("the values = %v; want the canonical realm and the default port", v.Raw())
	}
	if from, to := v.Range("relay_ports"); from != 49152 || to != 49999 {
		t.Fatalf("the default relay range = %d-%d", from, to)
	}
	refused := map[string]map[string]string{
		"realm":            {},
		"realm ":           {"realm": "not a host"},
		"port":             {"realm": "t.example.com", "port": "80"},
		"port ":            {"realm": "t.example.com", "port": "3478 "},
		"port  ":           {"realm": "t.example.com", "port": "03478"},
		"relay_ports":      {"realm": "t.example.com", "relay_ports": "50000-49999"},
		"relay_ports ":     {"realm": "t.example.com", "relay_ports": "1024-65535"},
		"relay_ports  ":    {"realm": "t.example.com", "relay_ports": "49152"},
		`"image"`:          {"realm": "t.example.com", "image": "docker.io/evil/evil"},
		"udp port 49152":   {"realm": "t.example.com", "port": "49152"},
		`"realm\nno-auth"`: {"realm": "t.example.com", "realm\nno-auth": "x"},
		"realm  ":          {"realm": "t.example.com\nno-auth"},
		"relay_ports   ":   {"realm": "t.example.com", "relay_ports": "49152-49999\nno-auth"},
	}
	for key, raw := range refused {
		_, err := TURN.Validate(raw)
		var oe *OptionError
		if !errors.Is(err, ErrBadOption) || !errors.As(err, &oe) || oe.Key != strings.TrimSpace(key) {
			t.Errorf("%v = %v; want ErrBadOption naming %s", raw, err, strings.TrimSpace(key))
		}
	}
}

func TestServiceNames(t *testing.T) {
	for _, ok := range []string{"turn", "a", "turn-2", "a" + strings.Repeat("b", 28)} {
		if !ValidName(ok) {
			t.Errorf("%q was refused", ok)
		}
		if u := UserOf(ok); len(u) > 32 {
			t.Errorf("the user of %q is %d characters; a user name holds 32", ok, len(u))
		}
	}
	for _, bad := range []string{"", "Turn", "2turn", "-turn", "turn_1", "turn.service", "../turn", "turn;id", "turn name", "a" + strings.Repeat("b", 29)} {
		if ValidName(bad) {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestTheTURNUnitIsConfined(t *testing.T) {
	v, err := TURN.Validate(map[string]string{"realm": "turn.example.com", "port": "3479", "relay_ports": "50000-50099"})
	if err != nil {
		t.Fatal(err)
	}
	q := quadlet(TURN, "turn", v)
	for _, want := range []string{
		"Image=docker.io/coturn/coturn@sha256:", "Exec=-c /etc/coturn/turnserver.conf --listening-port=3479 --min-port=50000 --max-port=50099 --realm=turn.example.com --use-auth-secret ",
		" --denied-peer-ip=127.0.0.0-127.255.255.255 ", " --denied-peer-ip=169.254.0.0-169.254.255.255 ", " --denied-peer-ip=10.0.0.0-10.255.255.255 ",
		" --no-tls ", "Network=host\n",
		"Volume=%h/config:/etc/coturn:ro,Z\n", "ReadOnly=true\n", "DropCapability=ALL\nAddCapability=NET_BIND_SERVICE\nNoNewPrivileges=true\n",
		"UserNS=keep-id\nUser=%U\nGroup=%G\n", "MemoryMax=128M\n", "Restart=always\n", "WantedBy=default.target\n",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("the unit lacks %q:\n%s", want, q)
		}
	}
	if n := strings.Count(q, "AddCapability"); n != 1 {
		t.Errorf("the unit keeps %d capabilities, want the one the image needs:\n%s", n, q)
	}
	for _, never := range []string{"PublishPort", "Privileged", "SecurityLabelDisable", "PodmanArgs", "allow-loopback-peers", "0123abcd", "static-auth-secret", "--no-dtls"} {
		if strings.Contains(q, never) {
			t.Errorf("the unit has %q:\n%s", never, q)
		}
	}
	// The file holds the secret and no setting: a relay that cannot read it
	// has no secret, and its command line still asks for one.
	conf := turnConf("0123abcd")
	if !strings.Contains(conf, "static-auth-secret=0123abcd\n") {
		t.Errorf("turnserver.conf lacks the secret:\n%s", conf)
	}
	for _, line := range strings.Split(strings.TrimSpace(conf), "\n") {
		if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "static-auth-secret=") {
			t.Errorf("turnserver.conf holds a setting, %q: settings belong on the command line", line)
		}
	}
	// A template that keeps nothing drops everything.
	bare := TURN
	bare.Keeps = nil
	if strings.Contains(quadlet(bare, "turn", v), "AddCapability") {
		t.Error("a template that keeps no capability has one")
	}
	// A template with a network of its own publishes its ports and nothing else.
	private := TURN
	private.Network = Private
	q = quadlet(private, "turn", v)
	if strings.Contains(q, "Network=host") || !strings.Contains(q, "PublishPort=3479:3479/udp\n") || !strings.Contains(q, "PublishPort=50000-50099:50000-50099/udp\n") {
		t.Errorf("a private template's unit:\n%s", q)
	}
}

// memStore is Store in memory.
type memStore struct {
	mu   sync.Mutex
	rows map[string]Service
}

func (m *memStore) All(context.Context) ([]Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Service
	for _, s := range m.rows {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) Get(_ context.Context, name string) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.rows[name]
	if !ok {
		return Service{}, ErrNotFound
	}
	return s, nil
}

func (m *memStore) Add(_ context.Context, s Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[s.Name]; ok {
		return ErrDuplicate
	}
	m.rows[s.Name] = s
	return nil
}

func (m *memStore) change(name string, fn func(*Service)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.rows[name]
	if !ok {
		return ErrNotFound
	}
	fn(&s)
	m.rows[name] = s
	return nil
}

func (m *memStore) SetOptions(_ context.Context, name string, o map[string]string) error {
	return m.change(name, func(s *Service) { s.Options = o })
}

func (m *memStore) SetState(_ context.Context, name string, st State) error {
	return m.change(name, func(s *Service) { s.State = st })
}

func (m *memStore) Remove(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[name]; !ok {
		return ErrNotFound
	}
	delete(m.rows, name)
	return nil
}

type memSecrets map[string][]byte

func (m memSecrets) Get(_ context.Context, name string) ([]byte, bool, error) {
	b, ok := m[name]
	return b, ok, nil
}
func (m memSecrets) Put(_ context.Context, name string, v []byte) error { m[name] = v; return nil }
func (m memSecrets) Delete(_ context.Context, name string) error        { delete(m, name); return nil }

// fakeHost records what the module asked of the machine.
type fakeHost struct {
	major, minor int
	podmanErr    error
	installErr   error
	calls        []string
	units        map[string]Unit
	running      map[string]bool
}

func (h *fakeHost) Podman(context.Context) (int, int, error) { return h.major, h.minor, h.podmanErr }

func (h *fakeHost) Install(_ context.Context, u Unit) error {
	h.calls = append(h.calls, "install "+u.Name)
	if h.installErr != nil {
		return h.installErr
	}
	h.units[u.Name] = u
	return nil
}

func (h *fakeHost) Start(_ context.Context, n string) error {
	h.calls = append(h.calls, "start "+n)
	h.running[n] = true
	return nil
}

func (h *fakeHost) Stop(_ context.Context, n string) error {
	h.calls = append(h.calls, "stop "+n)
	h.running[n] = false
	return nil
}

func (h *fakeHost) Restart(_ context.Context, n string) error {
	h.calls = append(h.calls, "restart "+n)
	h.running[n] = true
	return nil
}

func (h *fakeHost) Uninstall(_ context.Context, n string, purge bool) error {
	if purge {
		h.calls = append(h.calls, "purge "+n)
	} else {
		h.calls = append(h.calls, "uninstall "+n)
	}
	delete(h.units, n)
	delete(h.running, n)
	return nil
}

func (h *fakeHost) Running(_ context.Context, n string) (Running, error) {
	switch on, ok := h.running[n]; {
	case !ok:
		return Running{Active: "absent"}, nil
	case on:
		return Running{Active: "active", Sub: "running", MemoryBytes: 9 << 20}, nil
	}
	return Running{Active: "inactive", Sub: "dead"}, nil
}

func (h *fakeHost) Logs(_ context.Context, n string, limit int) ([]string, error) {
	h.calls = append(h.calls, "logs "+n)
	return make([]string, limit), nil
}

func (h *fakeHost) file(t *testing.T, service, path string) string {
	t.Helper()
	for _, f := range h.units[service].Files {
		if f.Path == path {
			return string(f.Body)
		}
	}
	t.Fatalf("%s has no file %s", service, path)
	return ""
}

func newTest() (*Module, *memStore, memSecrets, *fakeHost) {
	st := &memStore{rows: map[string]Service{}}
	sec := memSecrets{}
	h := &fakeHost{major: 5, minor: 4, units: map[string]Unit{}, running: map[string]bool{}}
	return NewModule(st, sec, h), st, sec, h
}

func TestDeployingTURN(t *testing.T) {
	ctx := context.Background()
	m, st, sec, h := newTest()
	v, err := m.deploy(ctx, Deploy{Template: "turn", Options: map[string]string{"realm": "turn.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "turn" || v.User != "ap-turn" || v.State != Deployed || v.Active != "active" || len(v.Ports) != 3 {
		t.Fatalf("the deployed service = %+v", v)
	}
	if got := strings.Join(h.calls, ", "); got != "install turn, restart turn" {
		t.Fatalf("the host was asked: %s", got)
	}
	secret := string(sec["service/turn/auth-secret"])
	if len(secret) != 64 {
		t.Fatalf("the generated secret is %d characters; want 32 bytes in hex", len(secret))
	}
	if conf := h.file(t, "turn", "config/turnserver.conf"); !strings.Contains(conf, "static-auth-secret="+secret+"\n") {
		t.Fatal("the configuration does not carry the generated secret")
	}
	if f := h.units["turn"].Files[0]; f.Mode != 0o400 {
		t.Fatalf("the configuration's mode = %o; it holds the secret", f.Mode)
	}
	h.file(t, "turn", ".config/containers/systemd/turn.container")

	// The same name again, a name that is none, a template that is none, and a
	// port another service has are each refused, with nothing asked of the host.
	h.calls = nil
	for want, p := range map[error]Deploy{
		ErrDuplicate:  {Template: "turn", Options: map[string]string{"realm": "b.example.com", "port": "4000", "relay_ports": "50000-50009"}},
		ErrBadName:    {Template: "turn", Name: "Turn;id", Options: map[string]string{"realm": "b.example.com"}},
		ErrNoTemplate: {Template: "shell", Options: map[string]string{"realm": "b.example.com"}},
		ErrPortTaken:  {Template: "turn", Name: "turn-2", Options: map[string]string{"realm": "b.example.com", "port": "4000"}},
		ErrBadOption:  {Template: "turn", Name: "turn-2", Options: map[string]string{"realm": "b.example.com", "port": "22"}},
	} {
		if _, err := m.deploy(ctx, p); !errors.Is(err, want) {
			t.Errorf("deploy %+v = %v; want %v", p, err, want)
		}
	}
	if len(h.calls) != 0 || len(st.rows) != 1 {
		t.Fatalf("a refused deploy reached the host (%v) or the store (%d rows)", h.calls, len(st.rows))
	}

	// An update keeps the secret and writes the new options.
	if _, err := m.update(ctx, Update{Name: "turn", Options: map[string]string{"realm": "turn.example.com", "port": "3479"}}); err != nil {
		t.Fatal(err)
	}
	conf := h.file(t, "turn", "config/turnserver.conf")
	if !strings.Contains(conf, "listening-port=3479\n") || !strings.Contains(conf, "static-auth-secret="+secret+"\n") {
		t.Fatalf("after the update:\n%s", conf)
	}
	if st.rows["turn"].Options["port"] != "3479" {
		t.Fatalf("the stored options = %v", st.rows["turn"].Options)
	}

	// The secret is given by its key, and no other.
	if s, err := m.secret(ctx, SecretAsk{Name: "turn", Key: "auth-secret"}); err != nil || s.Value != secret {
		t.Fatalf("services.secret = %q, %v", s.Value, err)
	}
	if _, err := m.secret(ctx, SecretAsk{Name: "turn", Key: "cloudflare_api_token"}); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("a key the template does not name = %v", err)
	}

	if v, err := m.stop(ctx, Ref{Name: "turn"}); err != nil || v.Active != "inactive" {
		t.Fatalf("stop = %+v, %v", v, err)
	}
	if v, err := m.start(ctx, Ref{Name: "turn"}); err != nil || v.Active != "active" {
		t.Fatalf("start = %+v, %v", v, err)
	}
	if _, err := m.restart(ctx, Ref{Name: "nothing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restarting no service = %v", err)
	}
	if l, err := m.logs(ctx, LogsAsk{Name: "turn", Limit: 100000}); err != nil || len(l.Lines) != 500 {
		t.Fatalf("logs with a huge limit = %d lines, %v; want 500", len(l.Lines), err)
	}
	if u, err := m.Users(ctx); err != nil || u["ap-turn"] != "turn" {
		t.Fatalf("Users = %v, %v", u, err)
	}

	h.calls = nil
	if _, err := m.remove(ctx, Remove{Name: "turn", Purge: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, ", "); got != "purge turn" || len(st.rows) != 0 || len(sec) != 0 {
		t.Fatalf("after remove: host %s, %d rows, %d secrets", got, len(st.rows), len(sec))
	}
	if _, err := m.remove(ctx, Remove{Name: "turn"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second remove = %v", err)
	}
}

// TestAnInterruptedDeployLeavesARowRemoveClears: the row is written before
// the host is touched, so a deploy that fails half-way is still listed, and
// remove cleans up whatever it left.
func TestAnInterruptedDeployLeavesARowRemoveClears(t *testing.T) {
	ctx := context.Background()
	m, st, sec, h := newTest()
	h.installErr = errors.New("useradd: no space left on device")
	if _, err := m.deploy(ctx, Deploy{Template: "turn", Options: map[string]string{"realm": "turn.example.com"}}); err == nil {
		t.Fatal("the deploy succeeded")
	}
	if s := st.rows["turn"]; s.State != Deploying {
		t.Fatalf("the row after a failed deploy = %+v; want deploying", s)
	}
	l, err := m.list(ctx, struct{}{})
	if err != nil || len(l) != 1 || l[0].State != Deploying || l[0].Active != "absent" {
		t.Fatalf("list = %+v, %v", l, err)
	}
	// update finishes it once the host can.
	h.installErr = nil
	if v, err := m.update(ctx, Update{Name: "turn", Options: map[string]string{"realm": "turn.example.com"}}); err != nil || v.State != Deployed {
		t.Fatalf("update after the failure = %+v, %v", v, err)
	}
	h.installErr = errors.New("again")
	if _, err := m.update(ctx, Update{Name: "turn", Options: map[string]string{"realm": "turn.example.com"}}); err == nil {
		t.Fatal("the update succeeded")
	}
	if _, err := m.remove(ctx, Remove{Name: "turn"}); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 0 || len(sec) != 0 || len(h.units) != 0 {
		t.Fatalf("after remove: %d rows, %d secrets, %d units", len(st.rows), len(sec), len(h.units))
	}
}

// TestAHostWithoutPodmanStillListens: deploy is refused with an error that
// says which, and the templates and the list still answer.
func TestAHostWithoutPodmanStillLists(t *testing.T) {
	ctx := context.Background()
	m, st, _, h := newTest()
	opts := map[string]string{"realm": "turn.example.com"}
	h.podmanErr = ErrNoPodman
	if _, err := m.deploy(ctx, Deploy{Template: "turn", Options: opts}); !errors.Is(err, ErrNoPodman) {
		t.Fatalf("deploy with no Podman = %v", err)
	}
	h.podmanErr, h.major, h.minor = nil, 4, 3
	if _, err := m.deploy(ctx, Deploy{Template: "turn", Options: opts}); !errors.Is(err, ErrOldPodman) {
		t.Fatalf("deploy with Podman 4.3 = %v", err)
	}
	if len(st.rows) != 0 || len(h.calls) != 0 {
		t.Fatalf("a refused deploy left %d rows and asked the host %v", len(st.rows), h.calls)
	}
	if ts, err := m.listTemplates(ctx, struct{}{}); err != nil || len(ts) != 1 || ts[0].Name != "turn" || len(ts[0].Options) != 3 {
		t.Fatalf("templates = %+v, %v", ts, err)
	}
	if l, err := m.list(ctx, struct{}{}); err != nil || len(l) != 0 {
		t.Fatalf("list = %+v, %v", l, err)
	}
	h.minor = 4
	if _, err := m.deploy(ctx, Deploy{Template: "turn", Options: opts}); err != nil {
		t.Fatalf("deploy with Podman 4.4 = %v", err)
	}
}

// TestEveryChangingVerbIsPrivileged: what changes the host, and what reveals
// a secret, is audited before it runs; the two reads are not.
func TestEveryChangingVerbIsPrivileged(t *testing.T) {
	open := map[string]bool{"services.templates": true, "services.list": true, "services.logs": true}
	for _, v := range NewModule(nil, nil, nil).Verbs() {
		if v.Privileged == open[v.Verb] {
			t.Errorf("%s: privileged = %v", v.Verb, v.Privileged)
		}
		if v.Privileged && v.Right != "services.deploy" {
			t.Errorf("%s names the right %q", v.Verb, v.Right)
		}
	}
}
