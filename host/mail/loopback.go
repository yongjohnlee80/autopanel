// Package mail is the machine side of mail: the loopback rule that keeps the
// mail stack's ports to the processes meant to reach them. Every command it
// runs is one of internal/hostcmd's tools, with arguments built from
// constants, numbers and the names the core validated.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// THE LOOPBACK RULE — rootless port forwarding delivers every connection to
// the mail stack from one address, whoever made it, so the PROXY header the
// gate writes is only as trustworthy as the set of processes that can open
// those ports. This table makes that set the gate alone, and the management
// port root's alone. It is a rule about loopback, not a firewall policy: it
// lets nothing in and opens nothing.
//
// It is kernel state: a reboot loses it, and a distribution's nftables
// service flushes it. So a oneshot unit loads it at boot, ordered after
// nftables and before the mail stack user's systemd (which only Wants it:
// Requires would pass a firewall restart on to the stack), restarting with
// nftables; and the core checks it at its start and at every reconcile.
//
// Decision: docs/decisions/mail.md#only-the-gate-reaches-the-mail-ports

// Table is the table's name, in the inet family.
const Table = "autopanel_loopback"

// The files the rule is installed as, under a root ("/" on a host).
const (
	RulesFile = "etc/autopanel/mail-loopback.nft"
	UnitName  = "autopanel-mail-loopback.service"
	unitFile  = "etc/systemd/system/" + UnitName
	dropIn    = "autopanel-mail.conf"
)

// Loopback is the rule for one host: who the gate is, whose systemd the mail
// stack runs under, and the ports.
type Loopback struct {
	Root      string // "/" on a host; a test's directory for the files
	GateUser  string // the gate's user, by name: nftables resolves it when it loads the file
	GateUID   int    // the same user's id, for the check (nftables lists ids)
	StackUID  int    // the mail stack user's id: its user@.service is ordered after the rule
	Forwarded []int  // the loopback ports only the gate may open: 10025, 10465, 10587, 10993
	Manage    int    // the management port only root may open: 18480
}

func (l Loopback) path(rel string) string { return filepath.Join(l.Root, rel) }

func (l Loopback) dropInFile() string {
	return "etc/systemd/system/user@" + strconv.Itoa(l.StackUID) + ".service.d/" + dropIn
}

func (l Loopback) valid() error {
	switch {
	case l.GateUser == "" || strings.ContainsAny(l.GateUser, "\"\\\n {};"):
		return errors.New("mail: the gate's user is not a plain name")
	case l.GateUID <= 0 || l.StackUID <= 0:
		return errors.New("mail: the gate's and the stack's users must be ordinary users")
	case len(l.Forwarded) == 0 || l.Manage <= 0:
		return errors.New("mail: the loopback rule needs its ports")
	}
	for _, p := range append(slices.Clone(l.Forwarded), l.Manage) {
		if p < 1024 || p > 65535 {
			return fmt.Errorf("mail: %d is no loopback port of the mail stack's", p)
		}
	}
	return nil
}

func (l Loopback) ports() string {
	ps := slices.Clone(l.Forwarded)
	slices.Sort(ps)
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// Rules is the file nft loads. Its first two lines make it idempotent: the
// table is made if missing, then deleted, then made whole, in one transaction.
func (l Loopback) Rules() string {
	return "# AutoPanel mail: only the gate reaches the mail stack's forwarded ports,\n" +
		"# only root its management port. Written by AutoPanel; loaded by " + UnitName + ".\n" +
		"table inet " + Table + "\n" +
		"delete table inet " + Table + "\n" +
		"table inet " + Table + " {\n" +
		"\tchain output {\n" +
		"\t\ttype filter hook output priority 0; policy accept;\n" +
		"\t\toifname \"lo\" tcp dport { " + l.ports() + " } meta skuid != \"" + l.GateUser + "\" drop\n" +
		"\t\toifname \"lo\" tcp dport " + strconv.Itoa(l.Manage) + " meta skuid != 0 drop\n" +
		"\t}\n" +
		"}\n"
}

// Unit is the oneshot that loads the rule at boot, and again whenever the
// distribution's nftables service restarts (and flushes it).
func (l Loopback) Unit() string {
	return `# AutoPanel mail: loads the loopback rule. Written by AutoPanel.
[Unit]
Description=AutoPanel mail: only the gate reaches the forwarded mail ports
After=nftables.service
PartOf=nftables.service
Before=user@` + strconv.Itoa(l.StackUID) + `.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /` + RulesFile + `
ExecStop=-/usr/sbin/nft delete table inet ` + Table + `

[Install]
WantedBy=multi-user.target
`
}

// DropIn orders the mail stack user's systemd after the rule. Wants, not
// Requires: Requires would restart the user's systemd, and the mail stack
// with it, whenever nftables restarts.
func (l Loopback) DropIn() string {
	return "# AutoPanel mail: the stack starts after the loopback rule. Written by AutoPanel.\n" +
		"[Unit]\nWants=" + UnitName + "\nAfter=" + UnitName + "\n"
}

// WriteFiles writes the rule, the unit and the drop-in under l.Root.
func (l Loopback) WriteFiles() error {
	if err := l.valid(); err != nil {
		return err
	}
	for _, f := range []struct {
		rel, text string
		mode      os.FileMode
	}{
		{RulesFile, l.Rules(), 0o600},
		{unitFile, l.Unit(), 0o644},
		{l.dropInFile(), l.DropIn(), 0o644},
	} {
		p := l.path(f.rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		tmp := p + ".autopanel-new"
		if err := os.WriteFile(tmp, []byte(f.text), f.mode); err != nil {
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

// Install writes the files and loads the rule now and at every boot.
func (l Loopback) Install(ctx context.Context) error {
	if err := l.WriteFiles(); err != nil {
		return err
	}
	if _, err := hostcmd.Run(ctx, hostcmd.Systemctl, "daemon-reload"); err != nil {
		return err
	}
	if _, err := hostcmd.Run(ctx, hostcmd.Systemctl, "enable", UnitName); err != nil {
		return err
	}
	// restart, not start: a unit already active (RemainAfterExit) would not run
	// again, and the file may have changed.
	_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "restart", UnitName)
	return err
}

// Remove takes the rule out of the kernel and its files off the host.
func (l Loopback) Remove(ctx context.Context) error {
	_, _ = hostcmd.Run(ctx, hostcmd.Systemctl, "disable", "--now", UnitName)
	for _, rel := range []string{RulesFile, unitFile, l.dropInFile()} {
		if err := os.Remove(l.path(rel)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = os.Remove(filepath.Dir(l.path(l.dropInFile()))) // only when empty
	if _, err := hostcmd.Run(ctx, hostcmd.Systemctl, "daemon-reload"); err != nil {
		return err
	}
	if st, err := l.Check(ctx); err == nil && st != StateMissing {
		if _, err := hostcmd.Run(ctx, hostcmd.Nft, "delete", "table", "inet", Table); err != nil {
			return err
		}
	}
	return nil
}

// State is what the kernel holds of the rule.
type State string

const (
	StateOK        State = "ok"        // the table, exactly as written
	StateMissing   State = "missing"   // no table: flushed, or never loaded
	StateDifferent State = "different" // a table of that name that is not the rule
)

// Check reads the table from the kernel and compares it with the rule.
func (l Loopback) Check(ctx context.Context) (State, error) {
	out, err := hostcmd.Run(ctx, hostcmd.Nft, "-j", "list", "table", "inet", Table)
	if err != nil {
		if code, ok := hostcmd.ExitCode(err); ok && code == 1 && strings.Contains(err.Error(), "No such file or directory") {
			return StateMissing, nil
		}
		return "", err
	}
	return l.compare(out)
}

// Ensure checks the rule and loads it again when the kernel does not hold it
// as written. It reports what it found; reloaded is true when it loaded it.
func (l Loopback) Ensure(ctx context.Context) (found State, reloaded bool, err error) {
	found, err = l.Check(ctx)
	if err != nil || found == StateOK {
		return found, false, err
	}
	if _, err := os.Stat(l.path(RulesFile)); err != nil {
		if err := l.WriteFiles(); err != nil {
			return found, false, err
		}
	}
	if _, err := hostcmd.Run(ctx, hostcmd.Nft, "-f", l.path(RulesFile)); err != nil {
		return found, false, err
	}
	return found, true, nil
}

// compare reads `nft -j list table` and reports whether it is the rule: one
// chain on the output hook at priority 0, policy accept, holding exactly the
// two rules, in order.
func (l Loopback) compare(listing []byte) (State, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return "", fmt.Errorf("mail: nft's listing does not parse: %w", err)
	}
	var chains []map[string]any
	var rules []string
	for _, item := range doc.Nftables {
		if raw, ok := item["chain"]; ok {
			var c map[string]any
			if err := json.Unmarshal(raw, &c); err != nil {
				return "", err
			}
			chains = append(chains, c)
		}
		if raw, ok := item["rule"]; ok {
			var r struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return "", err
			}
			rules = append(rules, fingerprint(r.Expr))
		}
	}
	if len(chains) != 1 {
		return StateDifferent, nil
	}
	c := chains[0]
	if c["name"] != "output" || c["type"] != "filter" || c["hook"] != "output" || c["policy"] != "accept" || num(c["prio"]) != "0" {
		return StateDifferent, nil
	}
	want := []string{
		"oifname==lo dport=={" + strings.ReplaceAll(l.ports(), " ", "") + "} skuid!=" + strconv.Itoa(l.GateUID) + " drop",
		"oifname==lo dport==" + strconv.Itoa(l.Manage) + " skuid!=0 drop",
	}
	if !slices.Equal(rules, want) {
		return StateDifferent, nil
	}
	return StateOK, nil
}

// fingerprint is a rule's expressions as one line, in the few shapes the rule
// uses: "oifname==lo dport=={10025,10993} skuid!=997 drop". Anything else
// shows as "?", so a rule of another shape never matches.
func fingerprint(exprs []map[string]json.RawMessage) string {
	parts := make([]string, 0, len(exprs))
	for _, e := range exprs {
		switch {
		case e["drop"] != nil:
			parts = append(parts, "drop")
		case e["match"] != nil:
			var m struct {
				Op   string `json:"op"`
				Left struct {
					Meta    *struct{ Key string } `json:"meta"`
					Payload *struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right json.RawMessage `json:"right"`
			}
			if json.Unmarshal(e["match"], &m) != nil {
				parts = append(parts, "?")
				continue
			}
			var left string
			switch {
			case m.Left.Meta != nil:
				left = m.Left.Meta.Key
			case m.Left.Payload != nil && m.Left.Payload.Protocol == "tcp":
				left = m.Left.Payload.Field
			default:
				parts = append(parts, "?")
				continue
			}
			parts = append(parts, left+m.Op+right(m.Right))
		default:
			parts = append(parts, "?")
		}
	}
	return strings.Join(parts, " ")
}

// right renders a match's right side: a string, a number, or a set of numbers.
func right(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var set struct {
		Set []json.Number `json:"set"`
	}
	if json.Unmarshal(raw, &set) == nil && set.Set != nil {
		ns := make([]int, 0, len(set.Set))
		for _, x := range set.Set {
			i, err := strconv.Atoi(x.String())
			if err != nil {
				return "?"
			}
			ns = append(ns, i)
		}
		slices.Sort(ns)
		s := make([]string, len(ns))
		for i, x := range ns {
			s[i] = strconv.Itoa(x)
		}
		return "{" + strings.Join(s, ",") + "}"
	}
	return "?"
}

func num(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
