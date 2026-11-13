package services

import (
	"reflect"
	"strings"
	"testing"
)

const chat = `
name: ignored
services:
  synapse:
    image: matrixdotorg/synapse:v1.2.3
    user: "991:991"
    environment:
      SYNAPSE_CONFIG_PATH: /data/homeserver.yaml
      DB_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./synapse:/data
      - media:/media:ro
    ports: ["127.0.0.1:8008:8008"]
    restart: unless-stopped
    mem_limit: 768m
    read_only: true
    cap_drop: [ALL]
    tmpfs: [/tmp]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8008/health"]
      interval: 30s
      retries: 3
  element:
    image: docker.io/vectorim/element-web@sha256:0000000000000000000000000000000000000000000000000000000000000001
    environment: ["ELEMENT_WEB_PORT=8080"]
    volumes: ["./element-config.json:/app/config.json:ro"]
    ports: ["8009:8080", "3478:3478/udp", "50000-50009:50000-50009/udp"]
    depends_on:
      synapse: {condition: service_started}
    command: nginx -g "daemon off;"
    entrypoint: ["/docker-entrypoint.sh"]
    env_file: [extra.env]
    working_dir: /app
    hostname: element
volumes:
  media:
`

func parsed(t *testing.T, text string, env map[string]string) Stack {
	t.Helper()
	st, findings := Parse([]byte(text), env)
	if refused(findings) {
		t.Fatalf("the file was refused: %+v", findings)
	}
	return st
}

func TestAComposeFileIsReadIntoItsSubset(t *testing.T) {
	st := parsed(t, chat, map[string]string{"DB_PASSWORD": "s3cret"})
	if len(st.Services) != 2 || st.Services[0].Name != "element" || st.Services[1].Name != "synapse" || !reflect.DeepEqual(st.Volumes, []string{"media"}) {
		t.Fatalf("the stack = %+v; want element and synapse, by name, and the volume", st)
	}
	e, s := st.Services[0], st.Services[1]
	if s.Image != "docker.io/matrixdotorg/synapse:v1.2.3" {
		t.Errorf("synapse's image = %q; want it under docker.io", s.Image)
	}
	if !s.HasUser || s.UID != 991 || s.GID != 991 || s.MemLimit != 768<<20 || !s.ReadOnly || s.Restart != "unless-stopped" {
		t.Errorf("synapse = %+v", s)
	}
	want := []EnvVar{{Key: "DB_PASSWORD", Value: "s3cret", FromEnv: true}, {Key: "SYNAPSE_CONFIG_PATH", Value: "/data/homeserver.yaml"}}
	if !reflect.DeepEqual(s.Environment, want) {
		t.Errorf("synapse's environment = %+v; want the value from .env marked", s.Environment)
	}
	if len(s.Volumes) != 2 || s.Volumes[0] != (Mount{Source: "synapse", Target: "/data"}) || s.Volumes[1] != (Mount{Source: "media", Named: true, Target: "/media", ReadOnly: true}) {
		t.Errorf("synapse's mounts = %+v", s.Volumes)
	}
	if h := s.Health; h == nil || h.Kind != "exec" || !reflect.DeepEqual(h.Args, []string{"curl", "-f", "http://localhost:8008/health"}) || h.Interval != "30s" || h.Retries != 3 {
		t.Errorf("synapse's health check = %+v; want the command without its CMD word", s.Health)
	}
	if p := s.Ports[0]; !p.Addr.IsLoopback() || p.HostFrom != 8008 || p.ContFrom != 8008 || p.Proto != "tcp" || p.Public() {
		t.Errorf("synapse's port = %+v", p)
	}
	if !reflect.DeepEqual(e.Command, []string{"nginx", "-g", "daemon off;"}) || !reflect.DeepEqual(e.Entrypoint, []string{"/docker-entrypoint.sh"}) {
		t.Errorf("element's command = %q, entrypoint %q", e.Command, e.Entrypoint)
	}
	if !reflect.DeepEqual(e.DependsOn, []string{"synapse"}) || !reflect.DeepEqual(e.EnvFile, []string{"extra.env"}) || e.WorkingDir != "/app" || e.Hostname != "element" {
		t.Errorf("element = %+v", e)
	}
	if r := e.Ports[2]; r.HostFrom != 50000 || r.HostTo != 50009 || r.Proto != "udp" || !r.Public() {
		t.Errorf("element's range = %+v", r)
	}
	if got := managedPaths(st); !reflect.DeepEqual(got, []string{"element-config.json", "extra.env"}) {
		t.Errorf("the managed paths = %v", got)
	}
	if got := dataPaths(st); !reflect.DeepEqual(got, []string{"synapse"}) {
		t.Errorf("the data paths = %v", got)
	}
}

// TestWhatTheSubsetDoesNotTakeIsRefusedByName: nothing a file says is dropped
// without a word. Each case is one service's body, or a whole file when it
// starts with "services:" or another top-level key.
func TestWhatTheSubsetDoesNotTakeIsRefusedByName(t *testing.T) {
	for body, want := range map[string]string{
		"image: a\nprivileged: true":                                             "unsupported-key services.x.privileged",
		"image: a\nbuild: .":                                                     "unsupported-key services.x.build",
		"image: a\ndevices: [/dev/sda]":                                          "unsupported-key services.x.devices",
		"image: a\nnetworks: [front]":                                            "unsupported-key services.x.networks",
		"image: a\nsecurity_opt: [seccomp=unconfined]":                           "unsupported-key services.x.security_opt",
		"image: a\npid: host":                                                    "unsupported-key services.x.pid",
		"image: a\nsysctls: {net.ipv4.ip_unprivileged_port_start: 0}":            "unsupported-key services.x.sysctls",
		"image: a\nnetwork_mode: bridge":                                         "unsupported-value services.x.network_mode",
		"image: a\nvolumes: [/etc:/host]":                                        "absolute-path services.x.volumes: /etc",
		"image: a\nvolumes: [/run/podman/podman.sock:/s]":                        "absolute-path services.x.volumes: /run/podman/podman.sock",
		"image: a\nvolumes: [../other:/o]":                                       "path-leaves-folder services.x.volumes: ../other",
		"image: a\nvolumes: [./a/../../b:/o]":                                    "path-leaves-folder services.x.volumes: ./a/../../b",
		"image: a\nvolumes: [./:/all]":                                           "whole-folder services.x.volumes",
		"image: a\nvolumes: [./.autopanel/x.env:/e]":                             "reserved-path services.x.volumes: ./.autopanel/x.env",
		"image: a\nvolumes: [data:/d]":                                           "undeclared-volume services.x.volumes: data",
		"image: a\nvolumes: [./d:/d:z]":                                          "unsupported-value services.x.volumes",
		"image: a\nvolumes: [{type: bind, source: ./d, target: /d}]":             "unsupported-key services.x.volumes: the long form",
		"image: a\nenv_file: /etc/passwd":                                        "absolute-path services.x.env_file: /etc/passwd",
		"image: a\nenv_file: ../x.env":                                           "path-leaves-folder services.x.env_file: ../x.env",
		"image: a\nuser: nobody":                                                 "user-not-numeric services.x.user",
		"image: a\nuser: \"991\"":                                                "user-not-numeric services.x.user",
		"image: a\ndepends_on: {y: {condition: service_healthy}}":                "unsupported-dependency services.x.depends_on.y.condition: service_healthy",
		"image: a\ndepends_on: {y: {condition: service_started, restart: true}}": "unsupported-dependency services.x.depends_on.y.restart: true",
		"image: a\nports: [\"80\"]":                                              "bad-port services.x.ports: 80",
		"image: a\nports: [\"8080:80/sctp\"]":                                    "bad-port services.x.ports: 8080:80/sctp",
		"image: a\nports: [\"1000-9000:1000-9000\"]":                             "bad-port services.x.ports: 1000-9000:1000-9000",
		"image: a\nports: [{target: 80, published: 8080}]":                       "unsupported-key services.x.ports: the long form",
		"image: a\nnetwork_mode: host\nports: [\"8080:80\"]":                     "host-network-port services.x.ports: 8080:80",
		"image: a\nnetwork_mode: host\nports: [\"127.0.0.1:8080:8080\"]":         "host-network-port services.x.ports: 127.0.0.1:8080:8080",
		"image: a\nenvironment: {A: \"x\\ny\"}":                                  "unit-text services.x.environment.A",
		"image: a\ncommand: [\"a\\nExecStartPre=/bin/evil\"]":                    "unit-text services.x.command",
		"image: a\nenvironment: {PASS: null}":                                    "env-no-value services.x.environment.PASS",
		"image: a\nenvironment: [PASS]":                                          "env-no-value services.x.environment.PASS",
		"image: a\nenvironment: {A: \"${NOT_SET}\"}":                             "unset-variable services.x.environment.A: ${NOT_SET}",
		"image: a\nrestart: on-failure:5":                                        "unsupported-value services.x.restart",
		"image: a\nmem_limit: lots":                                              "bad-value services.x.mem_limit",
		"image: a\nhealthcheck: {test: [\"CMD\"]}":                               "bad-value services.x.healthcheck.test",
		"image: a\nhealthcheck: {test: x, start_interval: 1s}":                   "unsupported-key services.x.healthcheck.start_interval",
		"image: \"a b\"":                                                         "bad-value image: a b",
		"restart: always":                                                        "no-image",
		"services: {x: {image: a}}\nnetworks: {front: {}}":                       "unsupported-key networks",
		"services: {x: {image: a}}\nsecrets: {s: {file: ./s}}":                   "unsupported-key secrets",
		"services: {x: {image: a}}\nvolumes: {v: {driver: nfs}}":                 "unsupported-key volumes.v",
		"services: {x: {image: a}}\nx-anchors: {a: 1}":                           "unsupported-key x-anchors",
		"services: {Web: {image: a}}":                                            "bad-service-name Web",
		"services: {}":                                                           "no-services",
		"volumes: {v: }":                                                         "no-services",
		"services: [a, b]":                                                       "bad-value services",
		"services: {x: {image: a, image: b}}":                                    "bad-value services.x.image: said twice",
		"services: {x: &a {image: a}, y: {<<: *a}}":                              "bad-value services.y: a key is not a plain string",
		"services:\n  x: {image: a\n":                                            "bad-yaml",
	} {
		text := body
		if !strings.HasPrefix(body, "services:") && !strings.HasPrefix(body, "volumes:") {
			text = "services:\n  x:\n    " + strings.ReplaceAll(body, "\n", "\n    ") + "\n"
		}
		_, findings := Parse([]byte(text), map[string]string{})
		found := false
		var got []string
		for _, f := range findings {
			line := strings.TrimSpace(f.ID + " " + f.Detail)
			got = append(got, line)
			found = found || (f.Severity == Refused && strings.HasPrefix(line, want))
		}
		if !found {
			t.Errorf("%q\n  findings = %q\n  want one that starts %q", body, got, want)
		}
	}
}

// TestAValueOfEnvInACommandIsWarnedOf: a command line can be read by every
// user of the host.
func TestAValueOfEnvInACommandIsWarnedOf(t *testing.T) {
	env := map[string]string{"SECRET": "s3cret"}
	for body, want := range map[string]bool{
		"command: [\"--auth\", \"${SECRET}\"]": true,
		"command: run --auth=${SECRET}":        true,
		"entrypoint: [\"/run\", \"$SECRET\"]":  true,
		"command: [\"--port\", \"8080\"]":      false,
		"environment: {AUTH: \"${SECRET}\"}":   false,
		"command: [\"echo\", \"$$SECRET\"]":    false,
	} {
		_, findings := Parse([]byte("services:\n  x:\n    image: a\n    "+body+"\n"), env)
		got := false
		for _, f := range findings {
			if f.Severity == Refused {
				t.Errorf("%q was refused: %+v", body, f)
			}
			got = got || (f.ID == "env-in-command" && f.Severity == Warning && !strings.Contains(f.Detail, "s3cret"))
		}
		if got != want {
			t.Errorf("%q: warned = %v; want %v", body, got, want)
		}
	}
}

func TestVariablesAreFilledFromEnvAlone(t *testing.T) {
	env := map[string]string{"A": "1", "EMPTY": ""}
	for in, want := range map[string]string{
		"x${A}y":           "x1y",
		"$A":               "1",
		"$$A":              "$A",
		"${B:-def}":        "def",
		"${B-def}":         "def",
		"${EMPTY:-def}":    "def",
		"${EMPTY-def}":     "",
		"${EMPTY}":         "",
		"100%":             "100%",
		"cost: $":          "cost: $",
		"${A}${A:-2}$A$$$": "111$$",
	} {
		got, _, missing := interpolate(in, env)
		if missing != "" || got != want {
			t.Errorf("interpolate(%q) = %q, missing %q; want %q", in, got, missing, want)
		}
	}
	for _, in := range []string{"${B}", "$B", "${A", "${A:+x}", "${}"} {
		if _, _, missing := interpolate(in, env); missing == "" {
			t.Errorf("interpolate(%q) was filled", in)
		}
	}
	if _, used, _ := interpolate("plain", env); used {
		t.Error("a value with no variable is marked as filled from .env")
	}
	t.Setenv("FROM_THE_CORE", "leak")
	if _, _, missing := interpolate("${FROM_THE_CORE}", env); missing != "FROM_THE_CORE" {
		t.Error("a variable of the core's own environment was filled")
	}
}

func TestAnEnvFileIsReadByLine(t *testing.T) {
	env, bad := ParseEnv([]byte("# a comment\nA=1\n B = two words \nQ=\"quoted\"\nS='single'\nEMPTY=\n\nnot a line\n1BAD=x\nURL=postgres://u:p@h/db?a=b\r\n"))
	want := map[string]string{"A": "1", "B": "two words", "Q": "quoted", "S": "single", "EMPTY": "", "URL": "postgres://u:p@h/db?a=b"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("env = %q", env)
	}
	if !reflect.DeepEqual(bad, []int{8, 9}) {
		t.Errorf("the lines that were not read = %v; want 8 and 9", bad)
	}
}

func TestACommandStringIsSplitAsAShellSplitsWords(t *testing.T) {
	for in, want := range map[string][]string{
		`a b  c`:               {"a", "b", "c"},
		`sh -c "echo hi; id"`:  {"sh", "-c", "echo hi; id"},
		`a 'b c' d`:            {"a", "b c", "d"},
		`a\ b`:                 {"a b"},
		`'it''s'`:              {"its"},
		`"" x`:                 {"", "x"},
		`"a\"b"`:               {`a"b`},
		`'a\b'`:                {`a\b`},
		`--flag="two words"`:   {"--flag=two words"},
		`  lead and trail   `:  {"lead", "and", "trail"},
		`$HOME stays as it is`: {"$HOME", "stays", "as", "it", "is"},
	} {
		if got, ok := split(in); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("split(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := split(`an "open quote`); ok {
		t.Error("an open quote was accepted")
	}
}

func TestImagesAreNamedInFull(t *testing.T) {
	p := &parser{}
	for in, want := range map[string]string{
		"nginx":                       "docker.io/library/nginx",
		"nginx:1.27":                  "docker.io/library/nginx:1.27",
		"matrixdotorg/synapse:v1":     "docker.io/matrixdotorg/synapse:v1",
		"ghcr.io/owner/app:v2":        "ghcr.io/owner/app:v2",
		"localhost/app":               "localhost/app",
		"registry.example.com:5000/a": "registry.example.com:5000/a",
	} {
		if got := p.image("x", in); got != want {
			t.Errorf("image(%q) = %q; want %q", in, got, want)
		}
	}
	for in, want := range map[string][2]string{
		"docker.io/library/nginx":                          {"docker.io/library/nginx", ":latest"},
		"docker.io/library/nginx:1.27":                     {"docker.io/library/nginx", ":1.27"},
		"registry.example.com:5000/a":                      {"registry.example.com:5000/a", ":latest"},
		"registry.example.com:5000/a:v1":                   {"registry.example.com:5000/a", ":v1"},
		"ghcr.io/o/a@sha256:" + strings.Repeat("0", 64):    {"ghcr.io/o/a", "@sha256:" + strings.Repeat("0", 64)},
		"ghcr.io/o/a:v1@sha256:" + strings.Repeat("0", 64): {"ghcr.io/o/a", "@sha256:" + strings.Repeat("0", 64)},
	} {
		if repo, pick := ImageRef(in); repo != want[0] || pick != want[1] {
			t.Errorf("ImageRef(%q) = %q, %q; want %q", in, repo, pick, want)
		}
	}
}

func TestSizes(t *testing.T) {
	for in, want := range map[string]int64{"512m": 512 << 20, "1g": 1 << 30, "2048k": 2048 << 10, "1073741824": 1 << 30, "64MB": 64 << 20, "1gb": 1 << 30} {
		if got, ok := parseSize(in); !ok || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "0", "-1m", "m", "1.5g", "99999999g", "1t"} {
		if _, ok := parseSize(in); ok {
			t.Errorf("parseSize(%q) was read", in)
		}
	}
}
