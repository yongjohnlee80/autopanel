package mail

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// DNS AND ITS RECORDS — every record a mail domain needs is kept in its zone
// by the core: published when the domain is added, kept in step, and only
// ever the records it published itself. A record of the same kind that
// AutoPanel did not write is never touched or given a sibling: the domain's
// records show it as different until the administrator takes it over.
//
// Decision: docs/decisions/mail.md#dns-is-kept-by-autopanel

// Record is one DNS record in zone-file terms: a fully qualified name without
// its final dot, a type, and the data as a zone file writes it after the type
// (MX "10 mail.example.com", SRV "0 1 993 mail.example.com", TXT its text
// unquoted, A an address).
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Remote is a record as the DNS provider holds it.
type Remote struct {
	ID string
	Record
}

// DNS is the zone's provider: Cloudflare, through the sealed token.
type DNS interface {
	// Zone is the provider's handle for the zone that holds name.
	Zone(ctx context.Context, name string) (string, error)
	Records(ctx context.Context, zone string) ([]Remote, error)
	Create(ctx context.Context, zone string, r Record) (id string, err error)
	Update(ctx context.Context, zone, id string, r Record) error
	Delete(ctx context.Context, zone, id string) error
}

// ErrNoDNS is a DNS with no token to publish with: every record is manual.
var ErrNoDNS = errors.New("mail: no DNS token: records are published by hand")

// Owned is a record AutoPanel published, as the store keeps it.
type Owned struct {
	Record
	RemoteID string
	Merged   bool // AutoPanel added to a record that was there (SPF), and did not create it
}

// RecordView is one record a domain needs, and where it stands.
type RecordView struct {
	Record
	Found string `json:"found"` // what the zone holds of that kind, when it is not Value
	State string `json:"state"` // ok, publishing, different, manual, failed
	Why   string `json:"why"`   // what the record is for
	Error string `json:"error,omitempty"`
}

// --- the zone file ----------------------------------------------------------

// parseZone reads the zone file Stalwart writes: one record per line, or a
// record whose data is split over lines inside parentheses (a long DKIM key).
func parseZone(text string) []Record {
	var out []Record
	var pending strings.Builder
	depth := 0
	flush := func(line string) {
		f := zoneFields(line)
		// name [ttl] [IN] type data...
		if len(f) < 3 {
			return
		}
		i := 1
		if isNumber(f[i]) {
			i++
		}
		if i < len(f) && strings.EqualFold(f[i], "IN") {
			i++
		}
		if i >= len(f)-1 {
			return
		}
		typ := strings.ToUpper(f[i])
		data := f[i+1:]
		r := Record{Name: fqdn(f[0]), Type: typ}
		switch typ {
		case "TXT":
			r.Value = strings.Join(data, "")
		case "MX", "SRV", "CNAME":
			for j := range data {
				data[j] = strings.TrimSuffix(data[j], ".")
			}
			r.Value = strings.ToLower(strings.Join(data, " "))
		default:
			r.Value = strings.Join(data, " ")
		}
		out = append(out, r)
	}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, ";"); i >= 0 && !strings.Contains(line[:i], `"`) {
			line = line[:i]
		}
		depth += strings.Count(line, "(") - strings.Count(line, ")")
		pending.WriteString(strings.NewReplacer("(", " ", ")", " ").Replace(line))
		pending.WriteString(" ")
		if depth <= 0 {
			flush(pending.String())
			pending.Reset()
			depth = 0
		}
	}
	return out
}

// zoneFields splits a zone line into fields, a quoted string being one field
// without its quotes.
func zoneFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case c == '"':
			inQuote = !inQuote
			have = true
			if !inQuote {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case (c == ' ' || c == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func fqdn(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

// --- what a domain needs ----------------------------------------------------

// kind tells records of one type apart where a name may hold several that
// mean different things: an apex holds an SPF TXT beside a verification TXT.
func kind(r Record) string {
	if r.Type != "TXT" {
		return r.Type
	}
	v := strings.ToLower(strings.TrimSpace(r.Value))
	for _, p := range []string{"v=spf1", "v=dmarc1", "v=tlsrptv1", "v=dkim1", "v=stsv1"} {
		if strings.HasPrefix(v, p) {
			return "TXT " + p
		}
	}
	return "TXT"
}

// why says what a record is for, in the panel's words.
func why(r Record) string {
	switch k := kind(r); {
	case r.Type == "MX":
		return "receives mail"
	case k == "TXT v=spf1":
		return "says who may send (SPF)"
	case k == "TXT v=dmarc1":
		return "says what to do with mail that fails (DMARC)"
	case k == "TXT v=dkim1":
		return "signs mail (DKIM)"
	case k == "TXT v=tlsrptv1":
		return "asks for TLS failure reports"
	case r.Type == "SRV":
		return "lets mail apps find the server"
	case r.Type == "A" || r.Type == "AAAA":
		return "the mail host's address"
	}
	return ""
}

// served is what a domain's zone must hold, from Stalwart's zone file: only
// what this host serves, DKIM never from here (AutoPanel publishes a key's
// record when its rotation says so), and DMARC with AutoPanel's policy.
func served(zone []Record, domain, host, dmarc string) []Record {
	var out []Record
	for _, r := range zone {
		switch {
		case r.Type == "MX" && r.Name == domain:
			out = append(out, r)
		case kind(r) == "TXT v=spf1" && r.Name == domain:
			out = append(out, Record{Name: domain, Type: "TXT", Value: "v=spf1 a:" + host + " -all"})
		case r.Type == "SRV" && (r.Name == "_imaps._tcp."+domain || r.Name == "_submissions._tcp."+domain):
			out = append(out, r)
		case kind(r) == "TXT v=tlsrptv1" && r.Name == "_smtp._tls."+domain:
			out = append(out, r)
		}
	}
	if dmarc == "" {
		dmarc = "quarantine"
	}
	out = append(out,
		Record{Name: "_dmarc." + domain, Type: "TXT", Value: "v=DMARC1; p=" + dmarc + "; rua=mailto:postmaster@" + domain},
		Record{Name: "_submission._tcp." + domain, Type: "SRV", Value: "0 1 587 " + host})
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Type < out[j].Name+out[j].Type })
	return out
}

// dkimFromZone is the DKIM record of each selector named, from Stalwart's
// zone file (which writes it with the public key Stalwart derived).
func dkimFromZone(zone []Record, domain string, selectors []string) []Record {
	want := map[string]bool{}
	for _, s := range selectors {
		want[s+"._domainkey."+domain] = true
	}
	var out []Record
	for _, r := range zone {
		if r.Type == "TXT" && want[r.Name] {
			out = append(out, r)
		}
	}
	return out
}

// hostRecords are the mail host's own: its address, and an SPF of its own
// (mail it sends as itself: bounces).
func hostRecords(host, ipv4 string) []Record {
	var out []Record
	if ipv4 != "" {
		out = append(out, Record{Name: host, Type: "A", Value: ipv4})
	}
	return append(out, Record{Name: host, Type: "TXT", Value: "v=spf1 a -all"})
}

// --- keeping a zone in step ------------------------------------------------

// same reports whether two values say the same, as DNS compares them.
func same(a, b Record) bool {
	if a.Type != b.Type || a.Name != b.Name {
		return false
	}
	norm := func(v string) string {
		return strings.Join(strings.Fields(strings.TrimSuffix(strings.ToLower(v), ".")), " ")
	}
	if a.Type == "TXT" {
		return strings.Join(strings.Fields(a.Value), " ") == strings.Join(strings.Fields(b.Value), " ")
	}
	return norm(a.Value) == norm(b.Value)
}

// keep makes zone hold want for one owner (a domain, or the mail host), and
// answers each record's state. It changes only records owned names; a record
// owned that is no longer wanted is deleted.
func (m *Module) keep(ctx context.Context, owner string, want []Record) ([]RecordView, error) {
	views := make([]RecordView, 0, len(want))
	for _, w := range want {
		views = append(views, RecordView{Record: w, State: "manual", Why: why(w)})
	}
	if m.dns == nil {
		return views, ErrNoDNS
	}
	zone, err := m.dns.Zone(ctx, owner)
	if err != nil {
		if !errors.Is(err, ErrNoDNS) {
			for i := range views {
				views[i].Error = err.Error()
			}
		}
		return views, err
	}
	remote, err := m.dns.Records(ctx, zone)
	if err != nil {
		return views, err
	}
	owned, err := m.store.Owned(ctx, owner)
	if err != nil {
		return views, err
	}
	ownedBy := map[string]Owned{}
	for _, o := range owned {
		ownedBy[o.Name+" "+o.Type+" "+kind(o.Record)] = o
	}
	for i, w := range want {
		k := w.Name + " " + w.Type + " " + kind(w)
		o, isOwned := ownedBy[k]
		delete(ownedBy, k)
		var kin []Remote // the zone's records of w's name, type and kind
		for _, r := range remote {
			if r.Name == w.Name && r.Type == w.Type && kind(r.Record) == kind(w) {
				kin = append(kin, r)
			}
		}
		var match, mine *Remote
		var foreign []Remote
		for j := range kin {
			switch {
			case isOwned && kin[j].ID == o.RemoteID:
				mine = &kin[j]
			case same(kin[j].Record, w):
				match = &kin[j]
			default:
				foreign = append(foreign, kin[j])
			}
		}
		v := &views[i]
		switch {
		case len(foreign) > 0: // never beside, nor over, a record AutoPanel did not write (H2)
			v.State, v.Found = "different", foreign[0].Value
		case mine != nil && o.Merged: // someone's SPF that AutoPanel added itself to (L1)
			v.Record.Value = o.Value
			if same(mine.Record, o.Record) {
				v.State = "ok"
			} else {
				v.State, v.Found = "different", mine.Value
			}
		case mine != nil && same(mine.Record, w):
			v.State = "ok"
		case mine != nil:
			if err := m.dns.Update(ctx, zone, mine.ID, w); err != nil {
				v.State, v.Error = "failed", err.Error()
				continue
			}
			v.State = "publishing"
			if err := m.store.PutOwned(ctx, owner, Owned{Record: w, RemoteID: mine.ID, Merged: o.Merged}); err != nil {
				return views, err
			}
		case match != nil:
			v.State = "ok" // the zone holds it already, as AutoPanel would have written it
		default:
			id, err := m.dns.Create(ctx, zone, w)
			if err != nil {
				v.State, v.Error = "failed", err.Error()
				continue
			}
			v.State = "publishing"
			if err := m.store.PutOwned(ctx, owner, Owned{Record: w, RemoteID: id}); err != nil {
				return views, err
			}
		}
	}
	// Owned records no longer wanted (a retired DKIM key, a removed domain).
	for _, o := range ownedBy {
		if o.Merged {
			// AutoPanel added to someone else's record: it gives the record back
			// as it found it is beyond what it knows, so it leaves it.
			_ = m.store.DeleteOwned(ctx, owner, o.Name, o.Type)
			continue
		}
		if err := m.dns.Delete(ctx, zone, o.RemoteID); err != nil && !notFound(err) {
			return views, fmt.Errorf("deleting %s %s: %w", o.Type, o.Name, err)
		}
		if err := m.store.DeleteOwned(ctx, owner, o.Name, o.Type); err != nil {
			return views, err
		}
	}
	return views, nil
}

// notFound reports a provider's answer that the record is gone already.
func notFound(err error) bool {
	return err != nil && (strings.Contains(err.Error(), " 404") || strings.Contains(err.Error(), "81044"))
}

// --- taking a record over ----------------------------------------------------

// mergeSPF adds a:host to an SPF record before its all term, and refuses a
// record that would then pass SPF's limit of 10 DNS lookups (L1).
func mergeSPF(existing, host string) (string, error) {
	terms := strings.Fields(existing)
	if len(terms) == 0 || !strings.EqualFold(terms[0], "v=spf1") {
		return "", errors.New("not an SPF record")
	}
	lookups := 1 // the term added
	for _, t := range terms[1:] {
		bare := strings.TrimLeft(strings.ToLower(t), "+-~?")
		if bare == "a:"+host || bare == "a:"+host+"." {
			return existing, nil // there already
		}
		for _, p := range []string{"include:", "a", "mx", "ptr", "exists:", "redirect="} {
			if bare == p || strings.HasPrefix(bare, p+":") || strings.HasPrefix(bare, p+"/") || (strings.HasSuffix(p, ":") || strings.HasSuffix(p, "=")) && strings.HasPrefix(bare, p) {
				lookups++
				break
			}
		}
	}
	if lookups > 10 {
		return "", fmt.Errorf("adding a:%s would make %d DNS lookups, past SPF's limit of 10", host, lookups)
	}
	out := []string{terms[0]}
	added := false
	for _, t := range terms[1:] {
		if !added && strings.HasSuffix(strings.ToLower(t), "all") {
			out = append(out, "a:"+host)
			added = true
		}
		out = append(out, t)
	}
	if !added {
		out = append(out, "a:"+host)
	}
	merged := strings.Join(out, " ")
	if len(merged) > 255 {
		return "", errors.New("the merged SPF record would pass 255 characters")
	}
	return merged, nil
}

// takeover replaces, in owner's zone, the records of w's name, type and kind
// that AutoPanel did not write, after the panel showed them: an SPF record is
// merged (AutoPanel adds itself to it); any other kind is deleted, and the
// next keep publishes w. host is the mail host, for the SPF merge.
func (m *Module) takeover(ctx context.Context, owner, host string, w Record) error {
	if m.dns == nil {
		return ErrNoDNS
	}
	zone, err := m.dns.Zone(ctx, owner)
	if err != nil {
		return err
	}
	remote, err := m.dns.Records(ctx, zone)
	if err != nil {
		return err
	}
	owned, err := m.store.Owned(ctx, owner)
	if err != nil {
		return err
	}
	mine := map[string]bool{}
	for _, o := range owned {
		mine[o.RemoteID] = true
	}
	var foreign []Remote
	for _, r := range remote {
		if r.Name == w.Name && r.Type == w.Type && kind(r.Record) == kind(w) && !mine[r.ID] && !same(r.Record, w) {
			foreign = append(foreign, r)
		}
	}
	if len(foreign) == 0 {
		return nil
	}
	if kind(w) == "TXT v=spf1" {
		merged, err := mergeSPF(foreign[0].Value, host)
		if err != nil {
			return err
		}
		r := Record{Name: w.Name, Type: "TXT", Value: merged}
		if err := m.dns.Update(ctx, zone, foreign[0].ID, r); err != nil {
			return err
		}
		return m.store.PutOwned(ctx, owner, Owned{Record: r, RemoteID: foreign[0].ID, Merged: true})
	}
	for _, f := range foreign {
		if err := m.dns.Delete(ctx, zone, f.ID); err != nil && !notFound(err) {
			return err
		}
	}
	return nil
}
