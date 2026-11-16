package stalwart

import (
	"strings"
	"testing"
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
