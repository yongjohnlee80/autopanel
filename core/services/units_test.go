package services

import (
	"strings"
	"testing"
)

func TestAUnitWordIsWrittenSoTheContainerGetsItAsItIs(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:       `"plain"`,
		`two words`:   `"two words"`,
		`a\b`:         `"a\\b"`,
		`say "hi"`:    `"say \"hi\""`,
		`100%`:        `"100%%"`,
		`%h/escape`:   `"%%h/escape"`,
		`$HOME`:       `"$$HOME"`,
		`a=b;c`:       `"a=b;c"`,
		``:            `""`,
		`trail\`:      `"trail\\"`,
		`'single'`:    `"'single'"`,
		`${VAR} $$ %`: `"$${VAR} $$$$ %%"`,
	} {
		if got := word(in); got != want {
			t.Errorf("word(%q) = %s; want %s", in, got, want)
		}
	}
	if got := value("sh", "-c", `echo "$1"`); got != `"sh" "-c" "echo \"$$1\""` {
		t.Errorf("value = %s", got)
	}
	if got := whole(`test -f /x && echo 100% $OK`); got != `test -f /x && echo 100%% $$OK` {
		t.Errorf("whole = %s", got)
	}
}

func TestAStackBecomesItsUnits(t *testing.T) {
	st := parsed(t, chat, map[string]string{"DB_PASSWORD": "s3cret"})
	digest := "sha256:" + strings.Repeat("a", 64)
	units, generated := units("chat", st, map[string]string{"synapse": digest})
	byPath := map[string]UnitFile{}
	for _, u := range units {
		byPath[u.Path] = u
	}
	if len(units) != 4 {
		t.Fatalf("%d units; want the network, the volume and two containers: %v", len(units), byPath)
	}
	if n := byPath[".config/containers/systemd/chat.network"]; n.Kind != KindNetwork || !strings.Contains(n.Body, "[Network]\nNetworkName=chat\n") {
		t.Errorf("the network unit = %+v", n)
	}
	if v := byPath[".config/containers/systemd/chat-media.volume"]; v.Kind != KindVolume || !strings.Contains(v.Body, "[Volume]\nVolumeName=chat-media\n") {
		t.Errorf("the volume unit = %+v", v)
	}
	s := byPath[".config/containers/systemd/chat-synapse.container"]
	for _, want := range []string{
		"Image=docker.io/matrixdotorg/synapse@" + digest + "\n",
		"ContainerName=chat-synapse\n",
		"Environment=\"SYNAPSE_CONFIG_PATH=/data/homeserver.yaml\"\n",
		"EnvironmentFile=%h/stack/.autopanel/synapse.env\n",
		"PublishPort=127.0.0.1:8008:8008/tcp\n",
		"Network=chat.network\nPodmanArgs=--network-alias=synapse\n",
		"Volume=%h/stack/synapse:/data\n", "Volume=chat-media.volume:/media:ro\n",
		"User=991\nGroup=991\nUserNS=keep-id:uid=991,gid=991\n",
		"ReadOnly=true\n", "DropCapability=ALL\n", "Tmpfs=/tmp\n", "NoNewPrivileges=true\n",
		"HealthCmd=[\"curl\",\"-f\",\"http://localhost:8008/health\"]\n", "HealthInterval=30s\n", "HealthRetries=3\n",
		"StartLimitIntervalSec=0\n",
		"[Service]\nRestart=always\nRestartSec=10\nTimeoutStartSec=600\nMemoryMax=805306368\nMemorySwapMax=0\n",
		"\n[Install]\nWantedBy=default.target\n",
	} {
		if !strings.Contains(s.Body, want) {
			t.Errorf("synapse's unit lacks %q:\n%s", want, s.Body)
		}
	}
	// The value .env filled is in the generated file, and nowhere in the unit.
	if strings.Contains(s.Body, "s3cret") || strings.Contains(s.Body, "DB_PASSWORD") {
		t.Errorf("synapse's unit holds a value from .env:\n%s", s.Body)
	}
	if len(generated) != 1 || generated[0].Path != "stack/.autopanel/synapse.env" || string(generated[0].Body) != "DB_PASSWORD=s3cret\n" || generated[0].Mode != 0o400 {
		t.Errorf("the generated files = %+v", generated)
	}
	if s.EnvSHA == "" || s.Digest != digest || s.Image != "docker.io/matrixdotorg/synapse:v1.2.3" || len(s.Ports) != 1 {
		t.Errorf("synapse's record = %+v", s)
	}
	if strings.Contains(s.Body, "HealthCmd=[\"CMD\"") {
		t.Error("the health check kept its CMD word: Podman reads such a list as one word")
	}

	e := byPath[".config/containers/systemd/chat-element.container"]
	for _, want := range []string{
		"Requires=chat-synapse.service\nAfter=chat-synapse.service\n",
		"Image=docker.io/vectorim/element-web@sha256:" + strings.Repeat("0", 63) + "1\n",
		"Exec=\"nginx\" \"-g\" \"daemon off;\"\n",
		"PodmanArgs=\"--entrypoint=[\\\"/docker-entrypoint.sh\\\"]\"\n",
		"Environment=\"ELEMENT_WEB_PORT=8080\"\n",
		"EnvironmentFile=%h/stack/extra.env\n",
		"PublishPort=8009:8080/tcp\n", "PublishPort=3478:3478/udp\n", "PublishPort=50000-50009:50000-50009/udp\n",
		"Volume=%h/stack/element-config.json:/app/config.json:ro\n",
		"WorkingDir=/app\n", "HostName=element\n", "[Service]\nRestart=no\n",
	} {
		if !strings.Contains(e.Body, want) {
			t.Errorf("element's unit lacks %q:\n%s", want, e.Body)
		}
	}
	for _, not := range []string{"User=", "MemoryMax=", "ReadOnly="} {
		if strings.Contains(e.Body, not) {
			t.Errorf("element's unit has %q, which its file did not ask for:\n%s", not, e.Body)
		}
	}
	if got := strings.Join(e.Inputs, ","); got != "extra.env,element-config.json" {
		t.Errorf("element's inputs = %s", got)
	}
	if got := withoutInstall(e.Body); strings.Contains(got, "[Install]") || !strings.HasSuffix(got, "TimeoutStartSec=600\n") {
		t.Errorf("a stopped service's unit =\n%s", got)
	}
}

func TestAHostNetworkServicePublishesNothing(t *testing.T) {
	st := parsed(t, "services:\n  relay:\n    image: coturn/coturn:4\n    network_mode: host\n    ports: [\"3478:3478/udp\", \"49160-49200:49160-49200/udp\"]\n", nil)
	units, _ := units("turn", st, nil)
	if len(units) != 1 {
		t.Fatalf("%d units; want the container alone, with no network of the stack's", len(units))
	}
	u := units[0]
	if !strings.Contains(u.Body, "Network=host\n") || strings.Contains(u.Body, "PublishPort") || strings.Contains(u.Body, "network-alias") {
		t.Errorf("the unit =\n%s", u.Body)
	}
	if len(u.Ports) != 2 || u.Ports[1] != (PortUse{Proto: "udp", From: 49160, To: 49200}) {
		t.Errorf("the ports it declares = %+v; they are claimed like published ones", u.Ports)
	}
	if !strings.Contains(u.Body, "Image=docker.io/coturn/coturn:4\n") {
		t.Errorf("with no digest yet, the unit names the tag:\n%s", u.Body)
	}
}

func TestTheServiceAUnitFileBecomes(t *testing.T) {
	for file, want := range map[string]string{
		".config/containers/systemd/chat-synapse.container": "chat-synapse.service",
		".config/containers/systemd/chat-media.volume":      "chat-media-volume.service",
		".config/containers/systemd/chat.network":           "chat-network.service",
	} {
		if got := ServiceUnit(file); got != want {
			t.Errorf("ServiceUnit(%q) = %q; want %q", file, got, want)
		}
	}
}

func refusals(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Severity == Refused {
			out = append(out, strings.TrimSpace(f.ID+" "+f.Service+" "+f.Detail))
		}
	}
	return out
}

func TestThePolicyRefuses(t *testing.T) {
	for body, c := range map[string]struct {
		facts Facts
		want  string
	}{
		"x: {image: a, cap_add: [NET_ADMIN]}":                                                  {want: "capability x NET_ADMIN"},
		"x: {image: a, cap_add: [SYS_ADMIN]}":                                                  {want: "capability x SYS_ADMIN"},
		"x: {image: a, cap_add: [ALL]}":                                                        {want: "capability x ALL"},
		"x: {image: a, ports: [\"80:8080\"]}":                                                  {want: "privileged-port x 80/tcp"},
		"x: {image: a, ports: [\"443:8443\"]}":                                                 {want: "privileged-port x 443/tcp"},
		"x: {image: a, network_mode: host, ports: [\"53:53/udp\"]}":                            {want: "privileged-port x 53/udp"},
		"x: {image: a, ports: [\"8080:80\"]}\n  y: {image: a, ports: [\"8080:81\"]}":           {want: "port-twice y 8080/tcp"},
		"x: {image: a, ports: [\"8000-8010:8000-8010\"]}":                                      {facts: Facts{Taken: []Claim{{Stack: "blog", PortUse: PortUse{Proto: "tcp", From: 8005, To: 8005}}}}, want: "port-taken x 8000-8010/tcp is stack blog's"},
		"x: {image: a, ports: [\"5432:5432\"]}":                                                {facts: Facts{Listening: []PortUse{{Proto: "tcp", From: 5432, To: 5432}}}, want: "port-in-use x 5432/tcp"},
		"x: {image: a, depends_on: [y]}":                                                       {want: "unknown-dependency x y"},
		"x: {image: a, depends_on: [x]}":                                                       {want: "unknown-dependency x x"},
		"x: {image: a, depends_on: [y]}\n  y: {image: a, depends_on: [x]}":                     {want: "dependency-cycle"},
		"network: {image: a}":                                                                  {want: "unit-name-taken network"},
		"x: {image: a, volumes: [\"./d:/d\"]}\n  y: {image: a, volumes: [\"./d/conf:/c:ro\"]}": {want: "data-overlap  d/conf is mounted read-only and d writable"},
		"x: {image: a, volumes: [\"./synapse:/data:ro\"]}":                                     {facts: Facts{Data: []string{"synapse"}}, want: "data-overlap  synapse would replace the stack's data in synapse"},
		"x: {image: a, volumes: [\"./synapse/media:/m:ro\"]}":                                  {facts: Facts{Data: []string{"synapse"}}, want: "data-overlap  synapse/media would replace"},
		"x: {image: a, volumes: [\"./conf:/c:ro\"]}":                                           {facts: Facts{Present: map[string]bool{"conf": true}}, want: "data-overlap  conf is in the stack's folder already"},
		"x: {image: a, volumes: [\"./d:/d\"]}":                                                 {facts: Facts{Links: []string{"d"}}, want: "symlink  d"},
		"x: {image: a, healthcheck: {test: [\"CMD\", \"NONE\"]}}":                              {want: "bad-value x healthcheck.test"},
		"x: {image: a, healthcheck: {test: \"[ -f /x ]\"}}":                                    {want: "bad-value x healthcheck.test"},
	} {
		st, parse := Parse([]byte("services:\n  "+body+"\n"), nil)
		if refused(parse) {
			t.Errorf("%q was refused by the parser: %v", body, refusals(parse))
			continue
		}
		got := refusals(check(st, c.facts))
		found := false
		for _, g := range got {
			found = found || strings.HasPrefix(g, c.want)
		}
		if !found {
			t.Errorf("%q\n  refusals = %q\n  want one that starts %q", body, got, c.want)
		}
	}

	// A port held by several sockets (IPv4 and IPv6, several addresses) is one finding.
	st, _ := Parse([]byte("services:\n  x: {image: a, ports: [\"5432:5432\"]}\n"), nil)
	held := PortUse{Proto: "tcp", From: 5432, To: 5432}
	if got := refusals(check(st, Facts{Listening: []PortUse{held, held, held}})); len(got) != 1 {
		t.Errorf("a port three sockets hold = %q; want one finding", got)
	}

	// A volume and a service whose units would be one systemd service.
	st, _ = Parse([]byte("services:\n  db-volume: {image: a, volumes: [\"db:/d\"]}\nvolumes: {db: }\n"), nil)
	if got := refusals(check(st, Facts{})); len(got) != 1 || !strings.HasPrefix(got[0], "unit-name-taken db-volume") {
		t.Errorf("a service named as a volume's unit: %q", got)
	}
}

func TestThePolicyAccepts(t *testing.T) {
	st := parsed(t, chat, map[string]string{"DB_PASSWORD": "x"})
	// What an apply of this very stack put in its folder is not data.
	facts := Facts{Managed: []string{"element-config.json", "extra.env"}, Present: map[string]bool{"element-config.json": true, "extra.env": true},
		Data: []string{"synapse"}, Listening: []PortUse{{Proto: "tcp", From: 22, To: 22}}}
	fs := check(st, facts)
	if got := refusals(fs); len(got) != 0 {
		t.Fatalf("the chat stack was refused: %q", got)
	}
	warnings := map[string]bool{}
	for _, f := range fs {
		warnings[strings.TrimSpace(f.ID+" "+f.Service)] = true
	}
	for _, want := range []string{"image-by-tag synapse", "public-port element", "no-memory-limit element", "writable-root element", "image-user element", "reach"} {
		if !warnings[want] {
			t.Errorf("no warning %q in %v", want, warnings)
		}
	}
	for _, not := range []string{"image-by-tag element", "public-port synapse", "no-memory-limit synapse", "image-user synapse", "host-network element"} {
		if warnings[not] {
			t.Errorf("the warning %q does not hold", not)
		}
	}
}

func TestWhatDependsOnAService(t *testing.T) {
	st := parsed(t, "services:\n  db: {image: a}\n  app: {image: a, depends_on: [db]}\n  web: {image: a, depends_on: [app]}\n  other: {image: a}\n", nil)
	units, _ := units("s", st, nil)
	if got := strings.Join(dependants(units, "db"), ","); got != "app,web" {
		t.Errorf("what needs db = %s; want app, and web through it", got)
	}
	if got := dependants(units, "web"); len(got) != 0 {
		t.Errorf("what needs web = %v", got)
	}
}

func TestAManifestIsItsFilesInOrder(t *testing.T) {
	a := NewManifest([]Input{{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}, {Path: ".env", Mode: 0o400, SHA256: "bb"}})
	b := NewManifest([]Input{{Path: ".env", Mode: 0o400, SHA256: "bb"}, {Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}})
	if a.SHA256 != b.SHA256 || a.Files[0].Path != ".env" {
		t.Errorf("the order the files were read in changed the manifest: %s, %s", a.SHA256, b.SHA256)
	}
	for what, files := range map[string][]Input{
		"a changed .env": {{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}, {Path: ".env", Mode: 0o400, SHA256: "cc"}},
		"a changed mode": {{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}, {Path: ".env", Mode: 0o444, SHA256: "bb"}},
		"a file more":    {{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}, {Path: ".env", Mode: 0o400, SHA256: "bb"}, {Path: "x", SHA256: "dd"}},
		"a file renamed": {{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}, {Path: "env", Mode: 0o400, SHA256: "bb"}},
		"no .env at all": {{Path: "compose.yaml", Mode: 0o400, SHA256: "aa"}},
	} {
		if NewManifest(files).SHA256 == a.SHA256 {
			t.Errorf("%s left the manifest's hash as it was", what)
		}
	}
	m := NewManifest([]Input{{Path: "conf/a", SHA256: "1"}, {Path: "conf/sub/b", SHA256: "2"}, {Path: "confx", SHA256: "3"}})
	o := NewManifest([]Input{{Path: "conf/a", SHA256: "1"}, {Path: "conf/sub/b", SHA256: "9"}, {Path: "confx", SHA256: "3"}})
	if m.sameUnder(o, "conf") || !m.sameUnder(o, "confx") || !m.sameUnder(o, "conf/a") {
		t.Error("sameUnder does not tell a folder's change from its neighbour's")
	}
}
