package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// zoneText is the zone file Stalwart v1.1 wrote for a new manual domain with
// one Ed25519 and one RSA key, names replaced with example ones.
const zoneText = `ap202611e._domainkey.example.net. IN TXT "v=DKIM1; k=ed25519; h=sha256; p=ngDxdFbJhp/xG2VDhZWD902hEYEKfkS7KrpJ7od6Uk4="
ap202611r._domainkey.example.net. IN TXT (
    "v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqT/k+6O5UOJPw0QEkDaSI0dEjXfMN0pkQDGBhIWmDT09QlfnpkYpvxTGZ2natMD4um6VMPlFZvqYHbvaNQCGsOIjCsViGPk6LYOZ2mGJYoKG6SSKSlf7DV97QtZ2XDdcIfTez/PdJE7SSVY2nyOhWhChyIjQSTI1XAWyNLyK56BGuHSW9dkTU2E"
    "XAn1p3pki11U3UfvGw9cdQrwFn2H6ADfWGIODwl/UgrGO3QfvGFFWQeZDKqVJWe2xV4z6uqMMDKkjHULlwsbQd5hl0X6fuOoyysdQenm0tA8Ga9P556afDY8xi71lyxl0lYHuNS5a/lSnsTW0UvOW4xsAtPC2JwIDAQAB"
)
mail.example.net. IN TXT "v=spf1 a -all"
example.net. IN TXT "v=spf1 mx -all"
example.net. IN MX 10 mail.example.net.
_dmarc.example.net. IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@example.net"
_caldavs._tcp.example.net. IN SRV 0 1 443 mail.example.net.
_imaps._tcp.example.net. IN SRV 0 1 993 mail.example.net.
_jmap._tcp.example.net. IN SRV 0 1 443 mail.example.net.
_pop3s._tcp.example.net. IN SRV 0 1 995 mail.example.net.
_submissions._tcp.example.net. IN SRV 0 1 465 mail.example.net.
mta-sts.example.net. IN CNAME mail.example.net.
_mta-sts.example.net. IN TXT "v=STSv1; id=5056112494975757486"
_smtp._tls.example.net. IN TXT "v=TLSRPTv1; rua=mailto:postmaster@example.net"
autoconfig.example.net. IN CNAME mail.example.net.
`

func TestParseZone(t *testing.T) {
	z := parseZone(zoneText)
	if len(z) != 15 {
		t.Fatalf("records: %d, want 15", len(z))
	}
	rsa := z[1]
	if rsa.Name != "ap202611r._domainkey.example.net" || !strings.HasPrefix(rsa.Value, "v=DKIM1; k=rsa;") || !strings.HasSuffix(rsa.Value, "IDAQAB") || strings.Contains(rsa.Value, `"`) {
		t.Fatalf("a split TXT is one value: %+v", rsa)
	}
	if mx := z[4]; mx.Type != "MX" || mx.Value != "10 mail.example.net" {
		t.Fatalf("MX: %+v", mx)
	}
}

func TestServedIsWhatThisHostServes(t *testing.T) {
	got := served(parseZone(zoneText), "example.net", "mail.example.net", "quarantine")
	var names []string
	for _, r := range got {
		names = append(names, r.Type+" "+r.Name+" "+r.Value)
	}
	want := []string{
		"TXT _dmarc.example.net v=DMARC1; p=quarantine; rua=mailto:postmaster@example.net",
		"SRV _imaps._tcp.example.net 0 1 993 mail.example.net",
		"TXT _smtp._tls.example.net v=TLSRPTv1; rua=mailto:postmaster@example.net",
		"SRV _submission._tcp.example.net 0 1 587 mail.example.net",
		"SRV _submissions._tcp.example.net 0 1 465 mail.example.net",
		"MX example.net 10 mail.example.net",
		"TXT example.net v=spf1 a:mail.example.net -all",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("served:\n%s\nwant:\n%s", strings.Join(names, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range got {
		if strings.Contains(r.Name, "_domainkey") {
			t.Fatal("DKIM never comes from the zone file's own list (M1)")
		}
	}
	if d := dkimFromZone(parseZone(zoneText), "example.net", []string{"ap202611e"}); len(d) != 1 || !strings.Contains(d[0].Value, "k=ed25519") {
		t.Fatalf("a named selector's record: %+v", d)
	}
}

func TestMergeSPF(t *testing.T) {
	for in, want := range map[string]string{
		"v=spf1 include:_spf.example.org ~all": "v=spf1 include:_spf.example.org a:mail.example.net ~all",
		"v=spf1 mx -all":                       "v=spf1 mx a:mail.example.net -all",
		"v=spf1 a:mail.example.net -all":       "v=spf1 a:mail.example.net -all",
		"v=spf1 ip4:192.0.2.1":                 "v=spf1 ip4:192.0.2.1 a:mail.example.net",
	} {
		got, err := mergeSPF(in, "mail.example.net")
		if err != nil || got != want {
			t.Errorf("mergeSPF(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	ten := "v=spf1"
	for i := 0; i < 10; i++ {
		ten += fmt.Sprintf(" include:s%d.example.org", i)
	}
	if _, err := mergeSPF(ten+" -all", "mail.example.net"); err == nil {
		t.Error("a merge past 10 lookups should be refused")
	}
	if _, err := mergeSPF("not spf", "mail.example.net"); err == nil {
		t.Error("only an SPF record merges")
	}
}

// fakeDNS is a zone in memory.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string]Remote
	next    int
	creates int
}

func newFakeDNS(rs ...Record) *fakeDNS {
	d := &fakeDNS{records: map[string]Remote{}}
	for _, r := range rs {
		d.next++
		id := fmt.Sprintf("foreign%d", d.next)
		d.records[id] = Remote{ID: id, Record: r}
	}
	return d
}
func (d *fakeDNS) Zone(context.Context, string) (string, error) { return "z", nil }
func (d *fakeDNS) Records(context.Context, string) ([]Remote, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Remote
	for _, r := range d.records {
		out = append(out, r)
	}
	return out, nil
}
func (d *fakeDNS) Create(_ context.Context, _ string, r Record) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.next++
	d.creates++
	id := fmt.Sprintf("r%d", d.next)
	d.records[id] = Remote{ID: id, Record: r}
	return id, nil
}
func (d *fakeDNS) Update(_ context.Context, _ string, id string, r Record) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[id] = Remote{ID: id, Record: r}
	return nil
}
func (d *fakeDNS) Delete(_ context.Context, _ string, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.records, id)
	return nil
}
func (d *fakeDNS) has(typ, name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, r := range d.records {
		if r.Type == typ && r.Name == name {
			out = append(out, r.Value)
		}
	}
	slices.Sort(out)
	return out
}

func states(vs []RecordView) map[string]string {
	out := map[string]string{}
	for _, v := range vs {
		out[v.Type+" "+v.Name] = v.State
	}
	return out
}

func TestKeepPublishesThenHolds(t *testing.T) {
	m, _, _, _, _, _ := newTestModule(t)
	ctx := context.Background()
	d := newFakeDNS(Record{Name: "example.net", Type: "TXT", Value: "google-site-verification=abc"})
	m.SetDNS(d)
	want := served(parseZone(zoneText), "example.net", "mail.example.net", "quarantine")
	vs, err := m.keep(ctx, "example.net", want)
	if err != nil || d.creates != len(want) {
		t.Fatalf("first pass: %d created of %d, %v", d.creates, len(want), err)
	}
	for k, s := range states(vs) {
		if s != "publishing" {
			t.Errorf("%s: %s, want publishing", k, s)
		}
	}
	vs, _ = m.keep(ctx, "example.net", want)
	for k, s := range states(vs) {
		if s != "ok" {
			t.Errorf("second pass %s: %s, want ok", k, s)
		}
	}
	if d.creates != len(want) {
		t.Fatal("a second pass created records again")
	}
	if got := d.has("TXT", "example.net"); len(got) != 2 {
		t.Fatalf("the verification TXT beside the SPF is untouched: %v", got)
	}
	// A wanted record that changes is updated in place; one no longer wanted goes.
	want2 := slices.Clone(want)
	for i := range want2 {
		if want2[i].Name == "_dmarc.example.net" {
			want2[i].Value = "v=DMARC1; p=reject; rua=mailto:postmaster@example.net"
		}
	}
	want2 = slices.DeleteFunc(want2, func(r Record) bool { return r.Name == "_smtp._tls.example.net" })
	if _, err := m.keep(ctx, "example.net", want2); err != nil {
		t.Fatal(err)
	}
	if got := d.has("TXT", "_dmarc.example.net"); len(got) != 1 || !strings.Contains(got[0], "p=reject") {
		t.Fatalf("DMARC updated in place: %v", got)
	}
	if got := d.has("TXT", "_smtp._tls.example.net"); len(got) != 0 {
		t.Fatalf("a record no longer wanted is deleted: %v", got)
	}
	// Removing the domain removes AutoPanel's records, and only them.
	if _, err := m.keep(ctx, "example.net", nil); err != nil {
		t.Fatal(err)
	}
	if left, _ := d.Records(ctx, "z"); len(left) != 1 || left[0].Value != "google-site-verification=abc" {
		t.Fatalf("after removal: %+v", left)
	}
}

func TestKeepNeverBesideAForeignRecord(t *testing.T) {
	m, _, _, _, _, _ := newTestModule(t)
	ctx := context.Background()
	d := newFakeDNS(
		Record{Name: "example.net", Type: "MX", Value: "10 mx.other.example"},
		Record{Name: "_dmarc.example.net", Type: "TXT", Value: "v=DMARC1; p=none"},
		Record{Name: "example.net", Type: "TXT", Value: "v=spf1 include:_spf.other.example ~all"},
	)
	m.SetDNS(d)
	want := served(parseZone(zoneText), "example.net", "mail.example.net", "quarantine")
	vs, err := m.keep(ctx, "example.net", want)
	if err != nil {
		t.Fatal(err)
	}
	st := states(vs)
	for _, k := range []string{"MX example.net", "TXT _dmarc.example.net", "TXT example.net"} {
		if st[k] != "different" {
			t.Errorf("%s: %s, want different", k, st[k])
		}
	}
	if got := d.has("MX", "example.net"); len(got) != 1 {
		t.Fatalf("no MX added beside another provider's (H2): %v", got)
	}
	if got := d.has("TXT", "_dmarc.example.net"); len(got) != 1 {
		t.Fatalf("no second DMARC record (H2): %v", got)
	}
	// Taking over: SPF merges, DMARC is replaced.
	if err := m.takeover(ctx, "example.net", "mail.example.net", Record{Name: "example.net", Type: "TXT", Value: "v=spf1 a:mail.example.net -all"}); err != nil {
		t.Fatal(err)
	}
	if err := m.takeover(ctx, "example.net", "mail.example.net", Record{Name: "_dmarc.example.net", Type: "TXT", Value: "v=DMARC1; p=quarantine"}); err != nil {
		t.Fatal(err)
	}
	vs, _ = m.keep(ctx, "example.net", want)
	st = states(vs)
	if st["TXT example.net"] != "ok" || st["TXT _dmarc.example.net"] != "publishing" || st["MX example.net"] != "different" {
		t.Fatalf("after taking SPF and DMARC over: %v", st)
	}
	if got := d.has("TXT", "example.net"); len(got) != 1 || got[0] != "v=spf1 include:_spf.other.example a:mail.example.net ~all" {
		t.Fatalf("the merged SPF: %v", got)
	}
	vs, _ = m.keep(ctx, "example.net", want) // a merged SPF stays merged
	if states(vs)["TXT example.net"] != "ok" {
		t.Fatal("a merged SPF was rewritten")
	}
}

func TestKeepWithoutDNSIsManual(t *testing.T) {
	m, _, _, _, _, _ := newTestModule(t)
	vs, err := m.keep(context.Background(), "example.net", served(parseZone(zoneText), "example.net", "mail.example.net", ""))
	if err != ErrNoDNS {
		t.Fatalf("err = %v", err)
	}
	for _, v := range vs {
		if v.State != "manual" || v.Why == "" {
			t.Fatalf("%+v: want manual, with why", v)
		}
	}
}

// dkimStalwart is a fake of Stalwart's DKIM, domain and certificate objects.
type dkimStalwart struct {
	mu    sync.Mutex
	keys  map[string]map[string]any // by id
	next  int
	certs map[string]map[string]any
}

func (s *dkimStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	answer := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, v, "c"}}})
	}
	set := func(store map[string]map[string]any) map[string]any {
		out := map[string]any{"created": map[string]any{}, "updated": map[string]any{}, "destroyed": []string{}}
		if c, ok := args["create"].(map[string]any); ok {
			for k, v := range c {
				s.next++
				id := fmt.Sprintf("x%d", s.next)
				obj := v.(map[string]any)
				obj["id"] = id
				store[id] = obj
				out["created"].(map[string]any)[k] = map[string]any{"id": id}
			}
		}
		if u, ok := args["update"].(map[string]any); ok {
			for id, v := range u {
				for k, val := range v.(map[string]any) {
					store[id][k] = val
				}
				out["updated"].(map[string]any)[id] = nil
			}
		}
		if d, ok := args["destroy"].([]any); ok {
			for _, id := range d {
				delete(store, id.(string))
			}
		}
		return out
	}
	switch method {
	case "x:DkimSignature/get":
		var list []any
		for _, k := range s.keys {
			list = append(list, k)
		}
		answer(map[string]any{"list": list})
	case "x:DkimSignature/set":
		answer(set(s.keys))
	case "x:Certificate/get":
		var list []any
		for _, c := range s.certs {
			list = append(list, c)
		}
		answer(map[string]any{"list": list})
	case "x:Certificate/set":
		out := set(s.certs)
		for _, c := range s.certs { // what Stalwart derives from the PEM
			if v, ok := c["certificate"].(map[string]any); ok {
				leaf := parsePEMLeaf(v["value"].(string))
				c["subjectAlternativeNames"] = map[string]bool{leaf.DNSNames[0]: true}
				c["notValidAfter"] = leaf.NotAfter.UTC().Format(time.RFC3339)
			}
		}
		answer(out)
	case "x:Action/set":
		answer(map[string]any{"created": map[string]any{"a": map[string]any{"id": "a"}}})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (s *dkimStalwart) stages() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, k := range s.keys {
		out[k["selector"].(string)] = k["stage"].(string)
	}
	return out
}

func TestDKIMRotation(t *testing.T) {
	m, st, _, _, h, _ := newTestModule(t)
	ctx := context.Background()
	fake := &dkimStalwart{keys: map[string]map[string]any{}, certs: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	m.base = srv.URL
	c := NewClient(srv.URL, Basic("a", "b"))
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	h.txt = map[string][]string{}

	// The zone file Stalwart writes lists a DKIM record for each key.
	zoneFor := func() []Record {
		var z []Record
		for sel := range fake.stages() {
			z = append(z, Record{Name: sel + "._domainkey.example.net", Type: "TXT", Value: "v=DKIM1; k=x; p=KEY" + sel})
		}
		return z
	}

	sels, err := m.rotate(ctx, c, "example.net", "b", nil)
	if err != nil || len(sels) != 2 || !slices.Equal(sels, []string{"ap202611e", "ap202611r"}) {
		t.Fatalf("the first pair: %v, %v", sels, err)
	}
	for sel, stage := range fake.stages() {
		if stage != "pending" {
			t.Fatalf("%s is %s before its record resolves; want pending (M1)", sel, stage)
		}
	}
	rows, _ := st.DKIM(ctx, "example.net")
	if rows[0].Step != stepPublished {
		t.Fatalf("after its first pass a new key is published: %+v", rows)
	}

	// Settled, but not resolving: still pending.
	now = now.Add(settleBefore + time.Minute)
	if _, err := m.rotate(ctx, c, "example.net", "b", zoneFor()); err != nil {
		t.Fatal(err)
	}
	if fake.stages()["ap202611e"] != "pending" {
		t.Fatal("a key switched before its record resolved")
	}
	// Resolving: both switch to signing.
	for _, sel := range []string{"ap202611e", "ap202611r"} {
		h.txt[sel+"._domainkey.example.net"] = []string{"v=DKIM1; k=x; p=KEY" + sel}
	}
	if _, err := m.rotate(ctx, c, "example.net", "b", zoneFor()); err != nil {
		t.Fatal(err)
	}
	if s := fake.stages(); s["ap202611e"] != "active" || s["ap202611r"] != "active" {
		t.Fatalf("after resolving: %v", s)
	}

	// 90 days on: a new pair, and once it resolves the old one retires.
	now = now.Add(rotateAfter + time.Hour)
	if _, err := m.rotate(ctx, c, "example.net", "b", zoneFor()); err != nil {
		t.Fatal(err)
	}
	if len(fake.stages()) != 4 {
		t.Fatalf("a second pair after 90 days: %v", fake.stages())
	}
	for sel := range fake.stages() {
		h.txt[sel+"._domainkey.example.net"] = []string{"v=DKIM1; k=x; p=KEY" + sel}
	}
	now = now.Add(settleBefore + time.Minute)
	if _, err := m.rotate(ctx, c, "example.net", "b", zoneFor()); err != nil {
		t.Fatal(err)
	}
	s := fake.stages()
	second := "ap" + now.Format("200601") + "e"
	if s["ap202611e"] != "retiring" || s[second] != "active" {
		t.Fatalf("after the second pair resolved: %v", s)
	}
	// Retired keys stay published a week, then go.
	sels, _ = m.rotate(ctx, c, "example.net", "b", zoneFor())
	if len(sels) != 4 {
		t.Fatalf("retired keys are still published: %v", sels)
	}
	now = now.Add(retireAfter + time.Hour)
	sels, _ = m.rotate(ctx, c, "example.net", "b", zoneFor())
	if len(sels) != 2 || len(fake.stages()) != 2 {
		t.Fatalf("after a week the old pair is gone: %v, %v", sels, fake.stages())
	}
}

// fakeCerts hands out a certificate it makes.
type fakeCerts struct {
	cert  *tls.Certificate
	asked int
}

func (f *fakeCerts) For(context.Context, string) (*tls.Certificate, error) {
	f.asked++
	return f.cert, nil
}

func selfSigned(t *testing.T, host string, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func parsePEMLeaf(p string) *x509.Certificate {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil
	}
	c, _ := x509.ParseCertificate(b.Bytes)
	return c
}

func TestTheCertificateIsHandedOver(t *testing.T) {
	m, _, _, stacks, _, _ := newTestModule(t)
	ctx := context.Background()
	fake := &dkimStalwart{keys: map[string]map[string]any{}, certs: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := NewClient(srv.URL, Basic("a", "b"))
	first := selfSigned(t, "mail.example.net", time.Now().Add(60*24*time.Hour).Truncate(time.Second))
	certs := &fakeCerts{cert: first}
	m.SetCerts(certs)
	stacks.since = time.Now().Unix()

	state, err := m.syncCertificate(ctx, c, "mail.example.net")
	if err != nil || !strings.HasPrefix(state, "ok until") || stacks.restarts != 1 || len(fake.certs) != 1 {
		t.Fatalf("the first: %q, %v; restarts %d, certificates %d", state, err, stacks.restarts, len(fake.certs))
	}
	// The same certificate: nothing to do.
	if _, err := m.syncCertificate(ctx, c, "mail.example.net"); err != nil || stacks.restarts != 1 || len(fake.certs) != 1 {
		t.Fatalf("an unchanged certificate: restarts %d, certificates %d, %v", stacks.restarts, len(fake.certs), err)
	}
	// A renewal updates in place, with no restart.
	certs.cert = selfSigned(t, "mail.example.net", time.Now().Add(90*24*time.Hour).Truncate(time.Second))
	if _, err := m.syncCertificate(ctx, c, "mail.example.net"); err != nil || stacks.restarts != 1 || len(fake.certs) != 1 {
		t.Fatalf("a renewal: restarts %d, certificates %d, %v", stacks.restarts, len(fake.certs), err)
	}
}
