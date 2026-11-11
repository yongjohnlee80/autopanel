package keyslot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteKeyfile makes a new keyfile at path: 32 random bytes, 0600, in a 0700
// directory of its own. It refuses to overwrite one, since that would strand
// the service slot it opens.
//
// The keyfile lives outside the state directory: an archive of the store and
// the keyfile together is both halves of one envelope, a credential taken by
// someone who believed they were backing up a database.
func WriteKeyfile(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	k, err := random(KeySize)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(k); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return k, nil
}

// ErrKeyfileExposed is a keyfile another user could read or replace.
var ErrKeyfileExposed = errors.New("keyslot: the keyfile is readable or writable by another user")

// ReadKeyfile reads a keyfile, refusing one that isn't a regular file owned by
// this user with mode 0600 or tighter: the mode is checked, not documented.
func ReadKeyfile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyfileExposed
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, ErrKeyfileExposed
	}
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(k) != KeySize {
		return nil, fmt.Errorf("keyslot: %s is %d bytes, not a keyfile", path, len(k))
	}
	return k, nil
}
