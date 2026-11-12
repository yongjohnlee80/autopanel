package ui

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"
)

// fakeSecret is what the fake service answers for a relay's auth-secret.
const fakeSecret = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7"

// withRelay is a fake client whose service has one TURN relay deployed.
func withRelay() *fakeClient {
	f := newFakeClient()
	f.services = []Service{{Name: "turn", Template: "turn", State: "deployed", User: "ap-turn",
		Options: map[string]string{"realm": "turn.example.com", "port": "3478", "relay_ports": "49152-49999"},
		Ports:   []ServicePort{{Proto: "udp", From: 3478, To: 3478}, {Proto: "tcp", From: 3478, To: 3478}, {Proto: "udp", From: 49152, To: 49999}},
		Active:  "active", Sub: "running", Memory: 21 << 20}}
	return f
}

func (f *fakeClient) Services(context.Context) ([]Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Service(nil), f.services...), nil
}

func (f *fakeClient) ServiceTemplates(context.Context) ([]ServiceTemplate, error) {
	return []ServiceTemplate{{Name: "turn", Title: "autopanel.services.turn", Network: "host", Memory: "128M",
		Options: []ServiceOption{
			{Key: "realm", Label: "autopanel.services.turn.realm", Kind: "host"},
			{Key: "port", Label: "autopanel.services.turn.port", Kind: "port", Default: "3478"},
			{Key: "relay_ports", Label: "autopanel.services.turn.relayPorts", Kind: "port_range", Default: "49152-49999"},
		},
		Secrets: []string{"auth-secret"}}}, nil
}

func (f *fakeClient) DeployService(_ context.Context, s ServiceSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deployErr != nil {
		return f.deployErr
	}
	f.deployed = append(f.deployed, s)
	name := s.Name
	if name == "" {
		name = s.Template
	}
	f.services = append(f.services, Service{Name: name, Template: s.Template, Options: s.Options, State: "deployed",
		User: "ap-" + name, Active: "activating", Sub: "start"})
	return nil
}

func (f *fakeClient) UpdateService(_ context.Context, s ServiceSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changed = append(f.changed, s)
	return nil
}

func (f *fakeClient) ServiceUnit(_ context.Context, action, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unitAsks = append(f.unitAsks, action+" "+name)
	for i := range f.services {
		if f.services[i].Name == name && action == "stop" {
			f.services[i].Active, f.services[i].Sub, f.services[i].Memory = "inactive", "dead", 0
		}
	}
	return nil
}

func (f *fakeClient) RemoveService(_ context.Context, name string, purge bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ask := name
	if purge {
		ask += " purge"
	}
	f.removals = append(f.removals, ask)
	for i, s := range f.services {
		if s.Name == name {
			f.services = append(f.services[:i], f.services[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeClient) ServiceLogs(_ context.Context, name string) ([]string, error) {
	return []string{"Nov 12 09:00:01 host " + name + "[812]: listener opened on 0.0.0.0:3478", "Nov 12 09:00:02 host " + name + "[812]: relay ready"}, nil
}

func (f *fakeClient) ServiceSecret(_ context.Context, name, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secretAsk = append(f.secretAsk, name+"/"+key)
	return fakeSecret, nil
}

// asked is what the fake service was asked to do to services.
func (f *fakeClient) asked() (deployed, changed []ServiceSpec, units, removals, secrets []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ServiceSpec(nil), f.deployed...), append([]ServiceSpec(nil), f.changed...),
		append([]string(nil), f.unitAsks...), append([]string(nil), f.removals...), append([]string(nil), f.secretAsk...)
}

// openServices opens the services panel through the menu bar: Alt+S opens
// Services, d is "Deployed services…".
func openServices(t *testing.T, s *decltest.Screen, want string) {
	t.Helper()
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('s'))
	s.WaitForText(t, "Deployed services…")
	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, want)
}

func TestPortsText(t *testing.T) {
	got := portsText([]ServicePort{{Proto: "udp", From: 3478, To: 3478}, {Proto: "udp", From: 49152, To: 49999}})
	if got != "udp 3478, udp 49152-49999" {
		t.Errorf("portsText = %q", got)
	}
	if got := portsText(nil); got != "-" {
		t.Errorf("portsText(nil) = %q", got)
	}
}

func TestServiceState(t *testing.T) {
	for _, c := range []struct {
		s    Service
		want string
	}{
		{Service{State: "deployed", Active: "active", Sub: "running"}, "active (running)"},
		{Service{State: "deployed", Active: "failed", Sub: "failed"}, "failed"},
		{Service{State: "deployed", Active: "absent"}, "absent"},
		{Service{State: "deployed"}, "-"},
		{Service{State: "deploying", Active: "absent"}, "deploy unfinished"},
		{Service{State: "removing", Active: "active", Sub: "running"}, "removal unfinished"},
	} {
		if got := serviceState(inEnglish{}, c.s); got != c.want {
			t.Errorf("serviceState(%+v) = %q, want %q", c.s, got, c.want)
		}
	}
}

// TestTurnSpec: the form's fields trimmed, and an empty one left out, so the
// daemon's default stands or its refusal names the option.
func TestTurnSpec(t *testing.T) {
	got := turnSpec(" relay ", " turn.example.com ", "", " 50000-50099 ")
	want := ServiceSpec{Template: "turn", Name: "relay", Options: map[string]string{"realm": "turn.example.com", "relay_ports": "50000-50099"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("turnSpec = %+v, want %+v", got, want)
	}
}

// TestTheServicesPanel: the deployed services, a row each; a unit stopped;
// the secrets shown and forgotten; the log; a removal that asks first, and
// says whether the directory goes too.
func TestTheServicesPanel(t *testing.T) {
	f := withRelay()
	s := start(t, f)
	openServices(t, s, "active (running)")
	for _, part := range []string{"TURN relay", "ap-turn", "21.0 MiB", "udp 3478, tcp 3478", "1 rows"} {
		s.WaitForText(t, part)
	}

	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "turn stopped")
	s.WaitForText(t, "inactive (dead)")

	s.Keys(t, decltest.Rune('c'))
	s.WaitForText(t, "Secrets of turn")
	s.WaitForText(t, fakeSecret)
	s.WaitForText(t, "audit log")
	s.Keys(t, decltest.Rune('q'))
	s.WaitFor(t, "the secrets to leave the screen", func(sc string) bool { return !strings.Contains(sc, fakeSecret) })

	s.Keys(t, decltest.Rune('o'))
	s.WaitForText(t, "relay ready")
	s.WaitForText(t, "turn: 2 lines")
	s.Keys(t, decltest.Rune('q'))
	s.WaitFor(t, "the log to close", func(sc string) bool { return !strings.Contains(sc, "relay ready") })

	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "Its directory is kept")
	s.Keys(t, escape)
	s.WaitFor(t, "the question to close", func(sc string) bool { return !strings.Contains(sc, "Its directory is kept") })
	if _, _, _, removals, _ := f.asked(); len(removals) != 0 {
		t.Fatalf("removed without a yes: %v", removals)
	}

	s.Keys(t, decltest.Rune('D'))
	s.WaitForText(t, "delete its directory?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "turn removed, with its directory")
	s.WaitFor(t, "the table without the relay", func(sc string) bool { return !strings.Contains(sc, "ap-turn") })

	_, _, units, removals, secrets := f.asked()
	if !reflect.DeepEqual(units, []string{"stop turn"}) {
		t.Errorf("unit asks = %v", units)
	}
	if !reflect.DeepEqual(removals, []string{"turn purge"}) {
		t.Errorf("removals = %v", removals)
	}
	if !reflect.DeepEqual(secrets, []string{"turn/auth-secret"}) {
		t.Errorf("secret asks = %v", secrets)
	}
}

// TestDeployATurnRelayThroughTheForm: the form opens on the template's
// defaults; a refused deploy leaves it as typed with the reason; a deploy
// that goes through closes it, and the new relay is in the panel.
func TestDeployATurnRelayThroughTheForm(t *testing.T) {
	f := newFakeClient()
	f.deployErr = errors.New("an option was refused: realm: not a host name")
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('s'))
	s.WaitForText(t, "Deploy a TURN relay…")
	s.Keys(t, decltest.Rune('t'))
	s.WaitForText(t, "Realm: the domain name")
	for _, part := range []string{"Name (lower-case", "3478", "49152-49999"} {
		s.WaitForText(t, part)
	}

	s.Keys(t, decltest.Type("relay")...)
	s.Keys(t, tab)
	s.Keys(t, decltest.Type("turn.example.com")...)
	s.Keys(t, enter)
	s.WaitForText(t, "realm: not a host name")
	if !strings.Contains(s.String(), "turn.example.com") {
		t.Fatalf("a refused deploy cleared the form:\n%s", s)
	}

	f.mu.Lock()
	f.deployErr = nil
	f.mu.Unlock()
	s.Keys(t, enter)
	s.WaitForText(t, "relay is deployed")
	s.WaitFor(t, "the form to close", func(sc string) bool { return !strings.Contains(sc, "Realm: the domain name") })
	deployed, _, _, _, _ := f.asked()
	want := []ServiceSpec{{Template: "turn", Name: "relay",
		Options: map[string]string{"realm": "turn.example.com", "port": "3478", "relay_ports": "49152-49999"}}}
	if !reflect.DeepEqual(deployed, want) {
		t.Fatalf("deployed = %+v, want %+v", deployed, want)
	}

	openServices(t, s, "ap-relay")
	s.WaitForText(t, "activating (start)")
}

// TestChangeARelay: the form on a deployed relay has its options and no name
// field, and OK asks for an update of that relay.
func TestChangeARelay(t *testing.T) {
	f := withRelay()
	s := start(t, f)
	openServices(t, s, "active (running)")
	s.Keys(t, decltest.Rune('e'))
	s.WaitForText(t, "Change turn")
	s.WaitForText(t, "turn.example.com")
	if strings.Contains(s.String(), "Name (lower-case") {
		t.Fatalf("a deployed relay's name can be typed:\n%s", s)
	}
	s.Keys(t, decltest.Type("x")...) // the realm has the keyboard: turn.example.comx
	s.Keys(t, enter)
	s.WaitForText(t, "turn is changed and restarted")
	_, changed, _, _, _ := f.asked()
	want := []ServiceSpec{{Template: "turn", Name: "turn",
		Options: map[string]string{"realm": "turn.example.comx", "port": "3478", "relay_ports": "49152-49999"}}}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("changed = %+v, want %+v", changed, want)
	}
}
