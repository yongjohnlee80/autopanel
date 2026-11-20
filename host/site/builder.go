//go:build linux

package site

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/services"
	hostservices "github.com/yongjohnlee80/autopanel/host/services"
)

// BuilderStack is the name the builder's user is made under: ap-site. No
// stack may take it (services.BuiltIn).
const BuilderStack = "site"

// The bounds of one build (docs/decisions/site.md, "The builder").
const (
	buildMemory   = "512m"
	buildPids     = "256"
	buildSeconds  = 120
	buildFileSize = "10485760" // 10 MiB: no file larger
	buildScratch  = "size=64m"
	// The unit around the container is held a little above the container's
	// own limit, so that Podman's own processes are bounded too.
	unitMemoryMax = "768M"
)

// Runner runs a transient unit as a stack's user: services.Host.Transient.
type Runner interface {
	EnsureUser(ctx context.Context, name string) error
	HasImage(ctx context.Context, name, ref string) (bool, error)
	Pull(ctx context.Context, name, ref string) (string, error)
	Transient(ctx context.Context, name string, props []string, argv ...string) ([]byte, error)
}

var _ Runner = (*hostservices.Host)(nil)

// Builder runs a site's build: the kit's image, by digest, under ap-site's
// own systemd, in a container with no network.
type Builder struct {
	Host    Runner
	Image   string   // name@sha256:<64 hex>
	Command []string // the build's command; nil: the image's own
}

var imageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// ErrImage is an image that is not named by its digest.
var ErrImage = errors.New("site: the builder's image is named by its digest: name@sha256:…")

// Prepare makes the builder's user and pulls the image when it is missing.
func (b Builder) Prepare(ctx context.Context) error {
	if !imageRE.MatchString(b.Image) {
		return ErrImage
	}
	if err := b.Host.EnsureUser(ctx, BuilderStack); err != nil {
		return err
	}
	has, err := b.Host.HasImage(ctx, BuilderStack, b.Image)
	if err != nil || has {
		return err
	}
	got, err := b.Host.Pull(ctx, BuilderStack, b.Image)
	if err != nil {
		return err
	}
	if want := b.Image[strings.LastIndex(b.Image, "@")+1:]; got != want {
		return fmt.Errorf("site: the builder's image resolved to %s, not %s", got, want)
	}
	return nil
}

// Build runs the build of w and waits for it. theme is the directory of the
// owner's theme, or "" for none. What the build printed is answered, cut to
// its last lines, for the site's status.
func (b Builder) Build(ctx context.Context, w Work, theme string) (string, error) {
	if !imageRE.MatchString(b.Image) {
		return "", ErrImage
	}
	ctx, cancel := context.WithTimeout(ctx, buildSeconds*time.Second+30*time.Second)
	defer cancel()
	out, err := b.Host.Transient(ctx, BuilderStack, []string{"MemoryMax=" + unitMemoryMax, "MemorySwapMax=0"},
		podmanRun(w, theme, b.Image, b.Command)...)
	return tail(string(out), 40), err
}

// podmanRun is the container a build runs in: no network, a read-only root,
// no capability, no new privilege, bounded memory, processes, time, file size
// and scratch; the input and the theme read-only, the output the one place it
// writes. It never pulls: the image was prepared by digest.
func podmanRun(w Work, theme, image string, command []string) []string {
	mount := func(src, dst, mode string) string {
		return "--volume=" + src + ":" + dst + ":" + mode + ",nosuid,nodev,noexec"
	}
	args := []string{"/usr/bin/podman", "run", "--rm", "--pull=never",
		"--network=none", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
		"--memory=" + buildMemory, "--memory-swap=" + buildMemory, "--pids-limit=" + buildPids,
		fmt.Sprintf("--timeout=%d", buildSeconds), "--ulimit=fsize=" + buildFileSize + ":" + buildFileSize,
		"--user=0:0", // ap-site itself, in its own namespace: the one owner of the output
		"--env=ASTRO_TELEMETRY_DISABLED=1",
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev," + buildScratch,
		mount(w.Content, "/site/src/content", "ro"),
		mount(w.Out, "/site/dist", "rw"),
	}
	if theme != "" {
		args = append(args, mount(theme, "/site/src/theme", "ro"))
	}
	return append(append(args, image), command...)
}

// tail is the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func init() {
	if !services.BuiltIn(BuilderStack) {
		panic("site: the builder's user is not reserved from stacks")
	}
}
