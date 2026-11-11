package certs

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// Cloudflare is the DNS-01 provider for zones on Cloudflare. The token needs
// Zone.DNS:Write, scoped to the zones AutoPanel serves; it comes from the
// environment or a secret store, never a file in the repository (R8), and it
// is sent only to Cloudflare's API (R17).
func Cloudflare(apiToken string) (certmagic.DNSProvider, error) {
	if apiToken == "" {
		return nil, errors.New("certs: the Cloudflare API token is empty")
	}
	return &cloudflare.Provider{APIToken: apiToken}, nil
}
