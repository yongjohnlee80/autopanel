//go:build !linux

package app

import (
	"errors"
	"log/slog"
)

// Site serves a site's pages on Linux only: the swap it relies on is
// renameat2.
func Site(*slog.Logger) error { return errors.New("autopanel --site: Linux only") }
