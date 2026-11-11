// Package gate is the proxy gate's domain: routes, their canonical form, and the
// routing table the data plane reads. It holds no transport: the table is generic
// over the handler a host builds for each route.
package gate

import (
	"errors"
	"strings"
)

// ErrBadHost is a host name the gate refuses: empty, too long, not ASCII, or not
// made of DNS labels.
var ErrBadHost = errors.New("gate: not a valid host name")

// CanonicalHost is the form every routing decision uses (ADR §4.6, "routing is
// canonical before any decision"): lower case, the port and one trailing dot
// removed. An internationalised name must arrive in its ASCII (punycode) form,
// as browsers send it; anything else is refused rather than guessed at.
//
// It accepts a Host header ("Example.COM:443") or a bare name.
func CanonicalHost(h string) (string, error) {
	if len(h) > 260 { // a name is at most 253, plus ":65535" and a dot
		return "", ErrBadHost
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return "", ErrBadHost // also refuses IPv6 literals, which name no route
		}
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", ErrBadHost
	}
	h = strings.ToLower(h)
	for _, label := range strings.Split(h, ".") {
		if !validLabel(label) {
			return "", ErrBadHost
		}
	}
	return h, nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
