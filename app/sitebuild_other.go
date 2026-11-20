//go:build !linux

package app

import (
	"log/slog"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

// siteBuilds builds nothing off Linux.
func siteBuilds(Config, coresite.Store, *slog.Logger) (*coresite.Builds, error) { return nil, nil }
