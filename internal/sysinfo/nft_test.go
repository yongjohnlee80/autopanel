package sysinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func rulesetFixture(t *testing.T, name string, ufwActive bool) Ruleset {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "nft", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := ParseRuleset(f, ufwActive)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// TestRulesetKnowsUfwDockerAndAutoPanel: Ubuntu 24.04 with Docker running and
// mail's loopback table, ufw off and on (captured), holds nothing foreign; the
// same ruleset read as if ufw were off finds ufw's dropping input chains.
func TestRulesetKnowsUfwDockerAndAutoPanel(t *testing.T) {
	if rs := rulesetFixture(t, "ufw-off-docker.json", false); rs.Foreign != 0 {
		t.Errorf("ufw off, Docker: %d foreign", rs.Foreign)
	}
	if rs := rulesetFixture(t, "ufw-on-docker.json", true); rs.Foreign != 0 {
		t.Errorf("ufw on, Docker: %d foreign", rs.Foreign)
	}
	if rs := rulesetFixture(t, "ufw-on-docker.json", false); rs.Foreign != 2 {
		t.Errorf("ufw's INPUT chains with ufw not active: %d foreign, want the two chains", rs.Foreign)
	}
}

// A hand-written /etc/nftables.conf: a dropping input chain and its rules.
const handWritten = `{"nftables":[{"metainfo":{"version":"1.0.9"}},
{"table":{"family":"inet","name":"filter","handle":1}},
{"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
{"rule":{"family":"inet","table":"filter","chain":"input","handle":2,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"accept":null}]}},
{"rule":{"family":"inet","table":"filter","chain":"input","handle":3,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"DOCKER-USER"}}]}},
{"chain":{"family":"ip","table":"nat","name":"PREROUTING","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","handle":2,"expr":[{"dnat":{"addr":"192.0.2.1"}}]}}
]}`

// TestRulesetFindsAHandWrittenFirewall: the dropping chain and its rule are
// foreign; a pure jump to a known chain and a nat rule are not.
func TestRulesetFindsAHandWrittenFirewall(t *testing.T) {
	rs, err := ParseRuleset(strings.NewReader(handWritten), false)
	if err != nil || rs.Foreign != 2 {
		t.Fatalf("foreign = %d, %v", rs.Foreign, err)
	}
	if _, err := ParseRuleset(strings.NewReader("{"), false); err == nil {
		t.Error("a broken listing parsed")
	}
}

// TestWhichManager: the decision's table, row by row.
func TestWhichManager(t *testing.T) {
	foreign := Ruleset{Foreign: 1}
	cases := []struct {
		name   string
		facts  Facts
		want   string
		active bool
		limits []string
	}{
		{"both running", Facts{UfwInstalled: true, UfwActive: true, FirewalldInstalled: true, FirewalldActive: true}, "unknown", true, []string{LimitTwoManagers}},
		{"firewalld", Facts{FirewalldInstalled: true, FirewalldActive: true}, "firewalld", true, []string{}},
		{"firewalld, other tables", Facts{FirewalldInstalled: true, FirewalldActive: true, Ruleset: foreign}, "firewalld", true, []string{LimitOtherTables}},
		{"ufw, Docker", Facts{UfwInstalled: true, UfwActive: true, DockerActive: true}, "ufw", true, []string{LimitDocker}},
		{"ufw off over a ruleset", Facts{UfwInstalled: true, Ruleset: foreign}, "unknown", true, []string{}},
		{"ufw off (Ubuntu)", Facts{UfwInstalled: true}, "ufw", false, []string{}},
		{"firewalld stopped", Facts{FirewalldInstalled: true}, "firewalld", false, []string{}},
		{"nothing (Debian)", Facts{}, "none", false, []string{}},
		{"nothing but a ruleset", Facts{Ruleset: foreign}, "unknown", true, []string{}},
	}
	for _, c := range cases {
		m, active, limits := c.facts.Manager()
		if m != c.want || active != c.active || !reflect.DeepEqual(limits, c.limits) {
			t.Errorf("%s: %s %v %v, want %s %v %v", c.name, m, active, limits, c.want, c.active, c.limits)
		}
	}
}
