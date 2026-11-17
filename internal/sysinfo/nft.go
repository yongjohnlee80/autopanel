package sysinfo

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Ruleset is what `nft -j list ruleset` says matters to the manager's choice:
// how many filtering rules belong to no one the read knows.
type Ruleset struct {
	Foreign int // rules (and dropping input chains) that are not ufw's, Docker's, firewalld's or AutoPanel's
}

// errRuleset is a ruleset whose JSON did not parse.
var errRuleset = errors.New("sysinfo: the ruleset did not parse")

// nftObject is one entry of nft's JSON listing; only the parts read here.
type nftObject struct {
	Table *struct {
		Family string `json:"family"`
		Name   string `json:"name"`
	} `json:"table"`
	Chain *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Hook   string `json:"hook"`
		Policy string `json:"policy"`
	} `json:"chain"`
	Rule *struct {
		Family string            `json:"family"`
		Table  string            `json:"table"`
		Chain  string            `json:"chain"`
		Expr   []json.RawMessage `json:"expr"`
	} `json:"rule"`
}

// ParseRuleset reads `nft -j list ruleset` and counts the foreign rules.
// Known are: AutoPanel's own table (mail's loopback rule); firewalld's table;
// ufw's chains (ufw-*, ufw6-*) and, while ufw is active, the base INPUT
// chains it sets to drop; Docker's chains (DOCKER*); a base chain's rule that
// only jumps to a known chain; and every chain of type nat, which translates
// rather than filters. Anything else that filters is foreign: a rule in
// another chain, or an input chain that drops by policy.
//
// Decision: docs/decisions/firewall.md#which-manager
func ParseRuleset(r io.Reader, ufwActive bool) (Ruleset, error) {
	var doc struct {
		Nftables []nftObject `json:"nftables"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Ruleset{}, errRuleset
	}
	type key struct{ family, table, chain string }
	nat := map[key]bool{}
	var rs Ruleset
	for _, o := range doc.Nftables {
		c := o.Chain
		if c == nil || knownTable(c.Family, c.Table) {
			continue
		}
		if c.Type == "nat" {
			nat[key{c.Family, c.Table, c.Name}] = true
			continue
		}
		ufwInput := ufwActive && c.Name == "INPUT" && (c.Family == "ip" || c.Family == "ip6") && c.Table == "filter"
		if c.Hook == "input" && c.Policy == "drop" && !knownChain(c.Name) && !ufwInput {
			rs.Foreign++
		}
	}
	for _, o := range doc.Nftables {
		ru := o.Rule
		if ru == nil || knownTable(ru.Family, ru.Table) || knownChain(ru.Chain) || nat[key{ru.Family, ru.Table, ru.Chain}] {
			continue
		}
		if target, ok := onlyJump(ru.Expr); ok && knownChain(target) {
			continue
		}
		rs.Foreign++
	}
	return rs, nil
}

// knownTable is a table the read accounts for whole.
func knownTable(family, name string) bool {
	return (family == "inet" && name == "autopanel_loopback") || (family == "inet" && name == "firewalld")
}

// knownChain is ufw's or Docker's chain, by its name.
func knownChain(name string) bool {
	return strings.HasPrefix(name, "ufw-") || strings.HasPrefix(name, "ufw6-") || strings.HasPrefix(name, "DOCKER")
}

// onlyJump reports whether a rule's expressions are a jump or a goto and,
// at most, a counter: a base chain handing its packets to another chain.
func onlyJump(expr []json.RawMessage) (string, bool) {
	target := ""
	for _, e := range expr {
		var x map[string]json.RawMessage
		if json.Unmarshal(e, &x) != nil || len(x) != 1 {
			return "", false
		}
		for k, v := range x {
			switch k {
			case "counter":
			case "jump", "goto":
				var t struct {
					Target string `json:"target"`
				}
				if json.Unmarshal(v, &t) != nil || target != "" {
					return "", false
				}
				target = t.Target
			default:
				return "", false
			}
		}
	}
	return target, target != ""
}

// Facts are what decides which manager a host has.
type Facts struct {
	UfwInstalled, UfwActive             bool
	FirewalldInstalled, FirewalldActive bool
	DockerActive                        bool
	Ruleset                             Ruleset
}

// Manager is which manager the facts make the host's, whether it is active,
// and what the read cannot see: the first row of the decision's table that
// holds. An inactive manager over a ruleset that still filters is not "off":
// it is a ruleset nobody here manages.
//
// Decision: docs/decisions/firewall.md#which-manager
func (f Facts) Manager() (manager string, active bool, limits []string) {
	limits = []string{}
	if f.DockerActive {
		limits = append(limits, LimitDocker)
	}
	foreign := f.Ruleset.Foreign > 0
	switch {
	case f.FirewalldActive && f.UfwActive:
		return "unknown", true, append(limits, LimitTwoManagers)
	case f.FirewalldActive:
		if foreign {
			limits = append(limits, LimitOtherTables)
		}
		return "firewalld", true, limits
	case f.UfwActive:
		if foreign {
			limits = append(limits, LimitOtherTables)
		}
		return "ufw", true, limits
	case foreign:
		return "unknown", true, limits
	case f.UfwInstalled:
		return "ufw", false, limits
	case f.FirewalldInstalled:
		return "firewalld", false, limits
	}
	return "none", false, limits
}
