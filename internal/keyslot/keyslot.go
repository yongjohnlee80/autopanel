// Package keyslot holds AutoPanel's master key: a random 32-byte key that
// encrypts the store's secrets (certificate and ACME private keys, the
// Cloudflare token). It is never stored in the clear. Two LUKS-style slots
// each hold a wrapped copy (AutoDB's design, core/auth/keyslot.go):
//
//   - the passphrase slot, under a key derived from the root user's master
//     passphrase with Argon2id; the derivation's second half verifies the
//     passphrase, so the slot is also root's login;
//   - the service slot, under a key derived with HKDF from a 0600 keyfile
//     kept outside the state directory, so the daemon unlocks after a reboot
//     with nobody at the keyboard. It unlocks the key and authenticates nobody.
//
// Every ciphertext is AES-256-GCM with AAD naming what it is, so a blob moved
// to another row, slot or purpose fails to open (R5).
package keyslot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KeySize is the master key's size, and every derived key's.
const KeySize = 32

const (
	aadPassphraseSlot = "autopanel:keyslot:passphrase:v1"
	aadServiceSlot    = "autopanel:keyslot:service:v1"
	infoServiceKEK    = "autopanel:keyslot:service:kek:v1"
)

var (
	// ErrWrongPassphrase is a passphrase that doesn't open the slot. It says
	// nothing more: which check failed is not the caller's business.
	ErrWrongPassphrase = errors.New("keyslot: wrong passphrase")
	// ErrBadKeyfile is a keyfile that doesn't open the service slot.
	ErrBadKeyfile = errors.New("keyslot: the keyfile does not open the service slot")
	// ErrOpen is a ciphertext that fails to open: altered, or under another AAD or key.
	ErrOpen = errors.New("keyslot: ciphertext does not open")
)

// Params are Argon2id's cost parameters, stored with each slot so a later
// change of the defaults never strands an old slot.
type Params struct {
	Time    uint32 `json:"t"`
	MemKiB  uint32 `json:"m"`
	Threads uint8  `json:"p"`
}

// DefaultParams are RFC 9106's second recommended option: 64 MiB, one pass,
// four lanes. They fit the staging host's memory budget for a login.
var DefaultParams = Params{Time: 1, MemKiB: 64 * 1024, Threads: 4}

// PassphraseSlot is the master key wrapped under a passphrase.
type PassphraseSlot struct {
	Salt    []byte `json:"salt"`
	Params  Params `json:"params"`
	Digest  []byte `json:"digest"`  // SHA-256 of the derivation's auth half
	Wrapped []byte `json:"wrapped"` // nonce || AES-GCM(kek, master key)
}

// ServiceSlot is the master key wrapped under a keyfile.
type ServiceSlot struct {
	Wrapped []byte `json:"wrapped"`
}

// NewMasterKey makes a master key.
func NewMasterKey() ([]byte, error) { return random(KeySize) }

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// derive splits one Argon2id output into a key-encryption key and an auth half.
func derive(passphrase string, salt []byte, p Params) (kek, auth []byte) {
	out := argon2.IDKey([]byte(passphrase), salt, p.Time, p.MemKiB, p.Threads, 2*KeySize)
	return out[:KeySize], out[KeySize:]
}

// SealPassphrase wraps mk under passphrase.
func SealPassphrase(mk []byte, passphrase string, p Params) (PassphraseSlot, error) {
	if len(mk) != KeySize {
		return PassphraseSlot{}, fmt.Errorf("keyslot: a master key is %d bytes", KeySize)
	}
	salt, err := random(16)
	if err != nil {
		return PassphraseSlot{}, err
	}
	kek, auth := derive(passphrase, salt, p)
	digest := sha256.Sum256(auth)
	wrapped, err := Seal(kek, aadPassphraseSlot, mk)
	if err != nil {
		return PassphraseSlot{}, err
	}
	return PassphraseSlot{Salt: salt, Params: p, Digest: digest[:], Wrapped: wrapped}, nil
}

// OpenPassphrase verifies passphrase and unwraps the master key. The digest is
// compared in constant time before anything is decrypted.
func OpenPassphrase(s PassphraseSlot, passphrase string) ([]byte, error) {
	kek, auth := derive(passphrase, s.Salt, s.Params)
	digest := sha256.Sum256(auth)
	if subtle.ConstantTimeCompare(digest[:], s.Digest) != 1 {
		return nil, ErrWrongPassphrase
	}
	mk, err := Open(kek, aadPassphraseSlot, s.Wrapped)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return mk, nil
}

func serviceKEK(keyfile []byte) ([]byte, error) {
	if len(keyfile) != KeySize {
		return nil, ErrBadKeyfile
	}
	// No salt, by decision: the input is per-install random bytes used for one
	// purpose, and a stored salt would be one more file to lose. info separates it.
	return hkdf.Key(sha256.New, keyfile, nil, infoServiceKEK, KeySize)
}

// SealService wraps mk under keyfile.
func SealService(mk, keyfile []byte) (ServiceSlot, error) {
	kek, err := serviceKEK(keyfile)
	if err != nil {
		return ServiceSlot{}, err
	}
	w, err := Seal(kek, aadServiceSlot, mk)
	return ServiceSlot{Wrapped: w}, err
}

// OpenService unwraps the master key with keyfile.
func OpenService(s ServiceSlot, keyfile []byte) ([]byte, error) {
	kek, err := serviceKEK(keyfile)
	if err != nil {
		return nil, err
	}
	mk, err := Open(kek, aadServiceSlot, s.Wrapped)
	if err != nil {
		return nil, ErrBadKeyfile
	}
	return mk, nil
}

// Seal encrypts plaintext under key with AES-256-GCM, bound to aad. The
// result is nonce || ciphertext.
func Seal(key []byte, aad string, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce, err := random(g.NonceSize())
	if err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open decrypts what Seal made under key and aad.
func Open(key []byte, aad string, sealed []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, ErrOpen
	}
	pt, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte(aad))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Overhead is how many bytes Seal adds: the nonce and the tag.
const Overhead = 12 + 16

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("keyslot: a key is %d bytes", KeySize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
