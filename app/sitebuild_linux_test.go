//go:build linux

package app

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	hostsite "github.com/yongjohnlee80/autopanel/host/site"
)

// TestThePipelineKeepsAHeldBuildsFiles: the core's pipeline hands a held
// build's expected files to the host's directories, for the readers' group,
// and sweeps what is no longer kept.
func TestThePipelineKeepsAHeldBuildsFiles(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("this user's group has no name")
	}
	if got := groupOwner(g.Name); got.GID != os.Getgid() {
		t.Fatalf("groupOwner(%s) = %+v", g.Name, got)
	}
	if got := groupOwner("autopanel-no-such-group"); got != (Owner{}) {
		t.Fatalf("a group that is not there: %+v", got)
	}
	me := Owner{UID: os.Getuid(), GID: os.Getgid()}
	p := &sitePipeline{files: hostsite.Files{Dir: filepath.Join(t.TempDir(), "site"), Owner: me, Builder: me, Reader: groupOwner(g.Name)}}
	w, err := p.files.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Out, "index.html"), []byte("<h1>held</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := coresite.Job{Host: "blog.example.com", Ref: w}
	if _, err := p.TakeAway(job); err != nil {
		t.Fatal(err)
	}
	if err := p.PublishHeld(job, 7, 3, []string{"index.html"}, nil); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(p.files.HeldRoot(), coresite.HeldFile("blog.example.com", 7, 3, "index.html"))
	if data, err := os.ReadFile(kept); err != nil || string(data) != "<h1>held</h1>" {
		t.Fatalf("the held file: %q, %v", data, err)
	}
	if err := p.SweepHeld("blog.example.com", map[int64]int64{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kept); err == nil {
		t.Fatal("a held file nothing keeps was left")
	}
}
