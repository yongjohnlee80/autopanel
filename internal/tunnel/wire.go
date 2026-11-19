package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// How an agent reaches the gate: on the HTTPS port, told apart from a browser
// by the one protocol its handshake offers. Under that protocol the agent
// speaks HTTP/1.1 for two requests only: one to enrol, and one that turns the
// connection into the tunnel.
const (
	// ALPN is the TLS protocol name an agent's handshake offers, alone: how
	// the gate knows the handshake for an agent's. The gate does not answer
	// it; the same name is the Upgrade the agent then asks for.
	ALPN = "autopanel-tunnel/1"
	// EnrolPath takes a POST of an enrolment token; the key enrolled is the
	// one the handshake proved.
	EnrolPath = "/enrol"
	// ConnectPath, asked for with "Upgrade: " + ALPN, becomes the tunnel.
	ConnectPath = "/tunnel"
	// TargetsName is a name every agent answers: its targets' names, as a
	// JSON list. A target of the agent's file cannot be named so.
	TargetsName = ".targets"
)

// KeyDigest is how a public key is known: the SHA-256 of its
// SubjectPublicKeyInfo, in hex.
func KeyDigest(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ValidTarget reports whether n may name a target: 1 to 32 lower-case
// letters, digits and hyphens, starting with a letter.
func ValidTarget(n string) bool {
	if len(n) < 1 || len(n) > 32 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
