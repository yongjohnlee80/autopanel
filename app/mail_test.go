package app

import (
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/internal/cloudflare"
)

func TestCloudflareRecordsRoundTrip(t *testing.T) {
	long := "v=DKIM1; k=rsa; h=sha256; p=" + strings.Repeat("A", 380)
	for _, r := range []mail.Record{
		{Name: "example.com", Type: "MX", Value: "10 mail.example.com"},
		{Name: "_imaps._tcp.example.com", Type: "SRV", Value: "0 1 993 mail.example.com"},
		{Name: "example.com", Type: "TXT", Value: "v=spf1 a:mail.example.com -all"},
		{Name: "ap202611r._domainkey.example.com", Type: "TXT", Value: long},
		{Name: "mail.example.com", Type: "A", Value: "192.0.2.10"},
	} {
		cf := toCloudflare(r)
		if cf.Type == "A" && (cf.Proxied == nil || *cf.Proxied) {
			t.Errorf("%s: an address record for mail must not be proxied", r.Name)
		}
		if r.Type == "TXT" && len(r.Value) > 255 && !strings.HasPrefix(cf.Content, `"`) {
			t.Errorf("a long TXT is sent as strings: %q", cf.Content[:20])
		}
		// Cloudflare answers SRV with its data, MX with a priority beside.
		back := cf
		if r.Type == "SRV" {
			for k, v := range cf.Data {
				if n, ok := v.(int); ok {
					back.Data[k] = float64(n)
				}
			}
		}
		if got := fromCloudflare(back); got != r {
			t.Errorf("round trip of %+v: %+v", r, got)
		}
	}
	// What Cloudflare answers for a TXT it holds in two strings.
	got := fromCloudflare(cloudflare.Record{Type: "TXT", Name: "x.example.com", Content: `"v=DKIM1; p=AB" "CD"`})
	if got.Value != "v=DKIM1; p=ABCD" {
		t.Fatalf("joined: %q", got.Value)
	}
}
