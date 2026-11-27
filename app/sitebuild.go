//go:build linux

package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"sync"

	"github.com/yongjohnlee80/autopanel/core/services"
	coresite "github.com/yongjohnlee80/autopanel/core/site"
	hostservices "github.com/yongjohnlee80/autopanel/host/services"
	hostsite "github.com/yongjohnlee80/autopanel/host/site"
)

// sitePipeline is the core's builds on this host: host/site's directories and
// builder. The builder's user and its image are made ready at the first
// build, not at start, so a host with no site never makes them.
type sitePipeline struct {
	files   hostsite.Files
	builder hostsite.Builder

	once  sync.Once
	ready error
}

// siteUser is the serving process's user and group (deploy/autopanel-site.service).
const siteUser = "autopanel-site"

// Owner is a user by number, as host/site takes it.
type Owner = hostsite.Owner

func (p *sitePipeline) prepare(ctx context.Context) error {
	p.once.Do(func() {
		if p.ready = p.builder.Prepare(ctx); p.ready != nil {
			return
		}
		u, err := user.Lookup(services.UserOf(hostsite.BuilderStack))
		if err != nil {
			p.ready = err
			return
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		p.files.Builder = Owner{UID: uid, GID: gid}
		p.files.Reader = groupOwner(siteUser)
	})
	return p.ready
}

// groupOwner is the group of that name, as the owner of what its members
// read: the held files are the serving process's group's. With no such group
// it is root's (0): the files stay root's alone, and held pages answer as
// missing.
func groupOwner(name string) Owner {
	g, err := user.LookupGroup(name)
	if err != nil {
		return Owner{}
	}
	gid, _ := strconv.Atoi(g.Gid)
	return Owner{GID: gid}
}

func (p *sitePipeline) Prepare(host string) (coresite.Job, error) {
	if err := p.prepare(context.Background()); err != nil {
		return coresite.Job{}, fmt.Errorf("the builder: %w", err)
	}
	w, err := p.files.Fresh(host)
	return coresite.Job{Host: host, Ref: w}, err
}

func (p *sitePipeline) Input(j coresite.Job, name string, data []byte) error {
	return p.files.WriteContent(j.Ref.(hostsite.Work), name, data)
}

func (p *sitePipeline) Run(ctx context.Context, j coresite.Job) (string, error) {
	return p.builder.Build(ctx, j.Ref.(hostsite.Work), "")
}

func (p *sitePipeline) TakeAway(j coresite.Job) (string, error) {
	w := j.Ref.(hostsite.Work)
	return w.Out, p.files.TakeAway(w)
}

func (p *sitePipeline) Publish(j coresite.Job, m coresite.Manifest) error {
	w := j.Ref.(hostsite.Work)
	if err := p.files.Normalize(w); err != nil {
		return err
	}
	if err := p.files.WriteManifest(w, m); err != nil {
		return err
	}
	if _, err := p.files.Swap(w); err != nil {
		return err
	}
	return p.files.LinkContent(w.Host, m.ContentHost)
}

func (p *sitePipeline) PublishHeld(j coresite.Job, node, build int64, files, dirs []string) error {
	return p.files.PublishHeld(j.Ref.(hostsite.Work), node, build, files, dirs)
}

func (p *sitePipeline) SweepHeld(host string, keep map[int64]int64) error {
	return p.files.SweepHeld(host, keep)
}

func (p *sitePipeline) TakeDown(host string) error { return p.files.TakeDown(host) }
func (p *sitePipeline) Remove(host string) error   { return p.files.Remove(host) }

// siteBuilds is the site's builds, or nil when this core builds nothing: it
// does not run as root, or no kit image is named. The kit's image is named by
// AUTOPANEL_SITE_KIT (name@sha256:…) until the release names it in the
// binary; its scripts are the binary's own (KitScripts).
func siteBuilds(cfg Config, st coresite.Store, log *slog.Logger) (*coresite.Builds, error) {
	image := env("AUTOPANEL_SITE_KIT", "")
	if os.Getuid() != 0 || image == "" {
		return nil, nil
	}
	kit := coresite.Kit{Image: image, Scripts: KitScripts()}
	p := &sitePipeline{
		files:   hostsite.Files{Dir: SiteDir(), Owner: Owner{UID: 0, GID: 0}},
		builder: hostsite.Builder{Host: hostservices.New(cfg.Services, cfg.Stacks), Image: image},
	}
	return coresite.NewBuilds(st, p, kit, log), nil
}
