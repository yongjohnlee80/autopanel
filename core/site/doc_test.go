package site

import (
	"errors"
	"strings"
	"testing"
)

// TestALevelIsNeverChangedBySilence: a first publish with no level is
// private; an update with none keeps the level; an unknown level is refused,
// first publish or update.
func TestALevelIsNeverChangedBySilence(t *testing.T) {
	if got, err := Level("", nil); err != nil || got != Private {
		t.Fatalf("a first publish with no level: %q, %v; want private", got, err)
	}
	for _, have := range []string{Public, Protected, Internal, Private} {
		if got, err := Level("", &Doc{Visibility: have}); err != nil || got != have {
			t.Errorf("an update with no level of a %s document: %q, %v", have, got, err)
		}
		if got, err := Level(Public, &Doc{Visibility: have}); err != nil || got != Public {
			t.Errorf("an update naming public of a %s document: %q, %v", have, got, err)
		}
	}
	for _, bad := range []string{"Public", "secret", " public", "public ", "internal,private"} {
		if _, err := Level(bad, nil); !errors.Is(err, ErrBadLevel) {
			t.Errorf("level %q on a first publish: %v; want refused", bad, err)
		}
		if _, err := Level(bad, &Doc{Visibility: Public}); !errors.Is(err, ErrBadLevel) {
			t.Errorf("level %q on an update: %v; want refused", bad, err)
		}
	}
}

// TestOnlyLeavingPublicLowers: taking a document from public is the one move
// that takes it from readers who could fetch it as a file.
func TestOnlyLeavingPublicLowers(t *testing.T) {
	for _, from := range []string{Public, Protected, Internal, Private} {
		for _, to := range []string{Public, Protected, Internal, Private} {
			if got, want := Lowers(from, to), from == Public && to != Public; got != want {
				t.Errorf("Lowers(%s, %s) = %v", from, to, got)
			}
		}
	}
}

func TestADocumentsFields(t *testing.T) {
	ok := Doc{ID: 1, Site: 1, Parent: 1, Kind: KindDoc, Slug: "a-first-article", Format: Markdown, Owner: 7, Visibility: Private, Share: []int64{8, 9}}
	if err := ok.Check(); err != nil {
		t.Fatalf("a good document: %v", err)
	}
	with := func(change func(*Doc)) Doc {
		d := ok
		d.Share = append([]int64(nil), ok.Share...)
		change(&d)
		return d
	}
	many := make([]int64, MaxShare+1)
	for i := range many {
		many[i] = int64(100 + i)
	}
	for name, tc := range map[string]struct {
		d    Doc
		want error
	}{
		"no level":                        {with(func(d *Doc) { d.Visibility = "" }), ErrBadLevel},
		"an unknown format":               {with(func(d *Doc) { d.Format = "pdf" }), ErrBadFormat},
		"an empty slug":                   {with(func(d *Doc) { d.Slug = "" }), ErrBadSlug},
		"a slug with a capital":           {with(func(d *Doc) { d.Slug = "Article" }), ErrBadSlug},
		"a slug with a slash":             {with(func(d *Doc) { d.Slug = "a/b" }), ErrBadSlug},
		"a slug with a dot":               {with(func(d *Doc) { d.Slug = ".." }), ErrBadSlug},
		"a slug starting with a hyphen":   {with(func(d *Doc) { d.Slug = "-a" }), ErrBadSlug},
		"a slug too long":                 {with(func(d *Doc) { d.Slug = strings.Repeat("a", MaxSlug+1) }), ErrBadSlug},
		"no kind":                         {with(func(d *Doc) { d.Kind = "" }), ErrBadFormat},
		"a folder with a format":          {with(func(d *Doc) { d.Kind = KindFolder }), ErrBadFormat},
		"a share list on a public one":    {with(func(d *Doc) { d.Visibility = Public }), ErrBadShare},
		"a share list on an internal one": {with(func(d *Doc) { d.Visibility = Internal }), ErrBadShare},
		"a share list on a protected one": {with(func(d *Doc) { d.Visibility = Protected }), ErrBadShare},
		"the owner in the share list":     {with(func(d *Doc) { d.Share = []int64{8, 7} }), ErrBadShare},
		"a user twice in the share list":  {with(func(d *Doc) { d.Share = []int64{8, 8} }), ErrBadShare},
		"no user in the share list":       {with(func(d *Doc) { d.Share = []int64{0} }), ErrBadShare},
		"too many shared":                 {with(func(d *Doc) { d.Share = many }), ErrBadShare},
		"active Markdown":                 {with(func(d *Doc) { d.Active, d.Visibility, d.Share = true, Public, nil }), ErrActiveHeld},
		"active private html":             {with(func(d *Doc) { d.Active, d.Format = true, HTML }), ErrActiveHeld},
		"active protected html":           {with(func(d *Doc) { d.Active, d.Format, d.Visibility, d.Share = true, HTML, Protected, nil }), ErrActiveHeld},
		"active internal html":            {with(func(d *Doc) { d.Active, d.Format, d.Visibility, d.Share = true, HTML, Internal, nil }), ErrActiveHeld},
	} {
		if err := tc.d.Check(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v; want %v", name, err, tc.want)
		}
	}
	if err := with(func(d *Doc) { d.Active, d.Format, d.Visibility, d.Share = true, HTML, Public, nil }).Check(); err != nil {
		t.Errorf("an active public html document: %v", err)
	}
}

// TestAResourcesName: what an author may call a file, and each way a name
// could reach outside its document or stand in for one of the site's own
// files.
func TestAResourcesName(t *testing.T) {
	for _, good := range []string{"latency.chart.json", "images/flow.png", "a/b/c/d/e/f.png", "drain-flow.mmd", "그림.png", "My Notes.csv", "a_b.png", "x/_y.png"} {
		if err := ResourceName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for bad, want := range map[string]error{
		"":                       ErrBadResource,
		"/etc/passwd":            ErrBadResource,
		"../other/secret.png":    ErrBadResource,
		"a/../../b.png":          ErrBadResource,
		"a/./b.png":              ErrBadResource,
		"a//b.png":               ErrBadResource,
		"a/":                     ErrBadResource,
		`a\b.png`:                ErrBadResource,
		`..\secret`:              ErrBadResource,
		"a\x00.png":              ErrBadResource,
		"a\n.png":                ErrBadResource,
		"a\x7f.png":              ErrBadResource,
		"bad\xffutf8.png":        ErrBadResource,
		"a/b/c/d/e/f/g.png":      ErrBadResource,
		strings.Repeat("n", 201): ErrBadResource,
		"_doc.html":              ErrReservedName,
		"_unlock":                ErrReservedName,
		"_kit/mermaid.js":        ErrReservedName,
		"_frame/x.html":          ErrReservedName,
		"index.html":             ErrReservedName,
		"INDEX.HTML":             ErrReservedName,
		"%2e%2e/x":               nil, // not decoded here: these are bytes of a name, and stay inside the document
		"..%2fx":                 nil,
	} {
		if err := ResourceName(bad); !errors.Is(err, want) {
			t.Errorf("%q: %v; want %v", bad, err, want)
		}
	}
	// A whole set: a repeat, a repeat by case, and too many.
	if err := ResourceNames([]string{"a.png", "b/a.png", "c.csv"}); err != nil {
		t.Errorf("a good set: %v", err)
	}
	for name, set := range map[string][]string{
		"the same name twice":       {"a.png", "a.png"},
		"names that differ by case": {"Flow.png", "flow.PNG"},
	} {
		if err := ResourceNames(set); !errors.Is(err, ErrSameName) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ResourceNames([]string{"a.png", "../b.png"}); !errors.Is(err, ErrBadResource) {
		t.Errorf("a set with a bad name: %v", err)
	}
	many := make([]string, MaxResources+1)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i) + ".png"
	}
	if err := ResourceNames(many); !errors.Is(err, ErrTooMany) {
		t.Errorf("too many: %v", err)
	}
}

func TestPaths(t *testing.T) {
	for p, want := range map[string]string{"": "", "/": "", "guides": "guides", "/guides/install/": "guides/install"} {
		parts, err := SplitPath(p)
		if err != nil || strings.Join(parts, "/") != want {
			t.Errorf("%q: %v, %v", p, parts, err)
		}
	}
	deep := strings.TrimSuffix(strings.Repeat("a/", MaxDepth+2), "/")
	for p, want := range map[string]error{
		"a//b": ErrBadPath, "a/../b": ErrBadPath, "A": ErrBadPath, "a/b c": ErrBadPath, "a/_kit": ErrBadPath,
		deep: ErrTooDeep, strings.Repeat("a", MaxPath+1): ErrPathTooLong,
	} {
		if _, err := SplitPath(p); !errors.Is(err, want) {
			t.Errorf("%q: %v; want %v", p, err, want)
		}
	}
}
