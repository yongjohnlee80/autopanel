//go:build !linux

package app

import (
	"context"
	"log/slog"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

func serveSiteAuth(context.Context, *coresite.Module, *slog.Logger) error { return nil }
