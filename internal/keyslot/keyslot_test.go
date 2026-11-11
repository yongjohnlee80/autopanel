package keyslot

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// cheap keeps the tests fast; the cost parameters travel with the slot.
var cheap = Params{Time: 1, MemKiB: 1024, Threads: 1}

func TestThePassphraseSlotOpensOnlyWithItsPassphrase(t *testing.T) {
	mk, _ := NewMasterKey()
	s, err := SealPassphrase(mk, "correct horse battery staple", cheap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPassphrase(s, "correct horse battery staple")
	if err != nil || !bytes.Equal(got, mk) {
		t.Fatalf("OpenPassphrase = %x, %v", got, err)
	}
	if _, err := OpenPassphrase(s, "wrong horse"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a wrong passphrase = %v", err)
	}
	s.Wrapped[len(s.Wrapped)-1] ^= 1
	if _, err := OpenPassphrase(s, "correct horse battery staple"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("an altered slot opened: %v", err)
	}
}

func TestTheServiceSlotOpensOnlyWithItsKeyfile(t *testing.T) {
	mk, _ := NewMasterKey()
	dir := filepath.Join(t.TempDir(), "keys")
	kf, err := WriteKeyfile(filepath.Join(dir, "service.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteKeyfile(filepath.Join(dir, "service.key")); err == nil {
		t.Fatal("WriteKeyfile overwrote a keyfile")
	}
	s, err := SealService(mk, kf)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadKeyfile(filepath.Join(dir, "service.key"))
	if err != nil || !bytes.Equal(read, kf) {
		t.Fatalf("ReadKeyfile = %v", err)
	}
	if got, err := OpenService(s, read); err != nil || !bytes.Equal(got, mk) {
		t.Fatalf("OpenService = %v", err)
	}
	other, _ := NewMasterKey()
	if _, err := OpenService(s, other); !errors.Is(err, ErrBadKeyfile) {
		t.Fatalf("another keyfile opened the slot: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "service.key"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyfile(filepath.Join(dir, "service.key")); !errors.Is(err, ErrKeyfileExposed) {
		t.Fatalf("a group-readable keyfile was read: %v", err)
	}
}

func TestACiphertextOpensOnlyUnderItsOwnAAD(t *testing.T) {
	mk, _ := NewMasterKey()
	ct, err := Seal(mk, "autopanel:certblob:a:v1", []byte("private key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len("private key")+Overhead {
		t.Errorf("Overhead is wrong: %d", len(ct)-len("private key"))
	}
	if pt, err := Open(mk, "autopanel:certblob:a:v1", ct); err != nil || string(pt) != "private key" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := Open(mk, "autopanel:certblob:b:v1", ct); !errors.Is(err, ErrOpen) {
		t.Fatalf("a blob moved to another key opened: %v", err)
	}
	if _, err := Open(mk, "x", ct[:5]); !errors.Is(err, ErrOpen) {
		t.Fatalf("a short blob = %v", err)
	}
}
