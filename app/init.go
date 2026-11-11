package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/store"
)

// MinPassphrase is the master passphrase's shortest length. It guards every
// secret the store holds, and it is root's login.
const MinPassphrase = 12

// Init makes the store's root user and its master key: a passphrase slot from
// the passphrase read from in (one line; install.sh pipes it, so it never
// appears in argv or the environment), and a service slot under a new keyfile
// at cfg.Keyfile, so the daemon unlocks after a reboot. It refuses a store
// that is already initialized.
func Init(ctx context.Context, cfg Config, user string, in io.Reader) error {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	pass := strings.TrimRight(line, "\r\n")
	if len([]rune(pass)) < MinPassphrase {
		return fmt.Errorf("the master passphrase must be at least %d characters", MinPassphrase)
	}
	if user == "" {
		user = "root"
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, store.Config{Engine: cfg.Engine, Path: filepath.Join(cfg.StateDir, "autopanel.db"), DSN: cfg.DSN})
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.ServiceSlot(ctx); err == nil {
		return store.ErrInitialized
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	if _, err := os.Stat(cfg.Keyfile); err == nil {
		return fmt.Errorf("%s exists but the store has no keyslots: it opens nothing here; move it aside and run --init again", cfg.Keyfile)
	}
	mk, err := keyslot.NewMasterKey()
	if err != nil {
		return err
	}
	ps, err := keyslot.SealPassphrase(mk, pass, keyslot.DefaultParams)
	if err != nil {
		return err
	}
	kf, err := keyslot.WriteKeyfile(cfg.Keyfile)
	if err != nil {
		return fmt.Errorf("writing the keyfile: %w", err)
	}
	ss, err := keyslot.SealService(mk, kf)
	if err == nil {
		err = st.InitRoot(ctx, user, ps, ss)
	}
	if err != nil {
		_ = os.Remove(cfg.Keyfile) // a keyfile with no slot to open is only a liability
		return err
	}
	return nil
}
