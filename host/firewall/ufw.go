// Package firewall reads and changes this machine's firewall through the
// manager it has: ufw, or firewalld. Each change is a fixed argument shape
// built from a rule's validated fields, never a rule passed as text, and the
// same shape is what the panel shows when it gives the administrator the
// command to run instead.
//
// Decision: docs/decisions/firewall.md
package firewall

import (
	"errors"
	"net/netip"
	"strconv"

	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// The ways a rule cannot be turned into a manager's command.
var (
	ErrNotModelled = errors.New("firewall: the rule is not one AutoPanel can write; change it with the manager's own tool")
	ErrBadRule     = errors.New("firewall: the rule's fields do not make a rule")
)

// UfwAllow is ufw's argument list that makes r: an incoming allow from the
// fields, both families when no address and no single family is named.
func UfwAllow(r sysinfo.Rule) ([]string, error) {
	if r.Action != "allow" || r.Direction != "in" || r.Service != "" || r.Log != "" {
		return nil, ErrBadRule
	}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return nil, ErrBadRule
	}
	return ufwRule(r)
}

// UfwRevoke is ufw's argument list that deletes r, a rule read back from ufw,
// by its fields. A forwarding rule, or one the read could not model, is not
// AutoPanel's to delete.
func UfwRevoke(r sysinfo.Rule) ([]string, error) {
	if !r.Modelled || r.Direction == "route" {
		return nil, ErrNotModelled
	}
	args, err := ufwRule(r)
	if err != nil {
		return nil, err
	}
	return append([]string{"delete"}, args...), nil
}

// UfwDefault is ufw's argument list that sets the incoming default.
func UfwDefault(policy string) ([]string, error) {
	switch policy {
	case "deny", "reject", "allow":
		return []string{"default", policy, "incoming"}, nil
	}
	return nil, ErrBadRule
}

// UfwEnable is ufw's argument list that turns it on or off.
func UfwEnable(on bool) []string {
	if on {
		return []string{"--force", "enable"}
	}
	return []string{"disable"}
}

// ufwRule writes r in ufw's full grammar: action, direction and interface,
// logging, protocol, from, to, and the port or the app.
func ufwRule(r sysinfo.Rule) ([]string, error) {
	switch r.Action {
	case "allow", "deny", "reject", "limit":
	default:
		return nil, ErrBadRule
	}
	src, err := ufwAddr(r.Source, r.Family, r.Dest != "")
	if err != nil {
		return nil, err
	}
	dst, err := ufwAddr(r.Dest, r.Family, r.Source != "")
	if err != nil {
		return nil, err
	}
	args := []string{r.Action}
	switch r.Direction {
	case "in", "out":
		if r.Direction == "out" || r.Scope != "" {
			args = append(args, r.Direction)
			if r.Scope != "" {
				if !ifaceName(r.Scope) {
					return nil, ErrBadRule
				}
				args = append(args, "on", r.Scope)
			}
		}
	default:
		return nil, ErrBadRule
	}
	switch r.Log {
	case "":
	case "log", "log-all":
		args = append(args, r.Log)
	default:
		return nil, ErrBadRule
	}
	if r.Service != "" {
		if !appName(r.Service) {
			return nil, ErrBadRule
		}
		return append(args, "from", src, "to", dst, "app", r.Service), nil
	}
	switch r.Proto {
	case "":
	case "tcp", "udp":
		args = append(args, "proto", r.Proto)
	default:
		return nil, ErrBadRule
	}
	args = append(args, "from", src, "to", dst)
	switch {
	case r.From == 0 && r.To == 0:
	case r.From >= 1 && r.From <= r.To && r.To <= 65535:
		port := strconv.Itoa(r.From)
		if r.To != r.From {
			if r.Proto == "" {
				return nil, ErrBadRule // ufw takes a range only with a protocol
			}
			port += ":" + strconv.Itoa(r.To)
		}
		args = append(args, "port", port)
	default:
		return nil, ErrBadRule
	}
	return args, nil
}

// ufwAddr is an address field as ufw takes it: "any" for both families, or
// when the other field's address names the family; the family's "any" prefix
// for one family alone; else the address in its normal form, which must be of
// the rule's family.
func ufwAddr(s, family string, otherSet bool) (string, error) {
	if s == "" {
		switch {
		case family == "both" || (otherSet && (family == "v4" || family == "v6")):
			return "any", nil
		case family == "v4":
			return "0.0.0.0/0", nil
		case family == "v6":
			return "::/0", nil
		}
		return "", ErrBadRule
	}
	n := sysinfo.NormalAddr(s)
	var a netip.Addr
	if p, err := netip.ParsePrefix(n); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(n); err != nil {
		return "", ErrBadRule
	}
	if (family == "v4" && !a.Is4()) || (family == "v6" && !a.Is6()) || family == "both" {
		return "", ErrBadRule // an address is one family's
	}
	return n, nil
}

// ifaceName is a Linux interface name: up to 15 bytes of letters, digits and
// . - _ (the kernel's IFNAMSIZ and what ufw accepts).
func ifaceName(s string) bool {
	return len(s) >= 1 && len(s) <= 15 && plain(s, ".-_")
}

// appName is a ufw application profile's name as ufw prints it.
func appName(s string) bool {
	return len(s) >= 1 && len(s) <= 64 && plain(s, ".-_ ")
}

// plain reports whether s is letters, digits and extra, starting with a letter
// or a digit, so no argument reads as an option.
func plain(s, extra string) bool {
	for i, c := range s {
		if i == 0 && !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		for _, e := range extra {
			ok = ok || c == e
		}
		if !ok {
			return false
		}
	}
	return true
}
