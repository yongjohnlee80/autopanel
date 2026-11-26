package site

import "errors"

// WHERE A NODE IS READ — by what its chain holds (the node and every folder
// above it). A reader proves who they are in one way a request: a grant's
// cookie belongs to the site's host, a session's to the app host, and no one
// request carries both. So a chain needs one kind of proof.
const (
	SurfacePublic = "public" // every node public: a static page of the site's host
	SurfaceSite   = "site"   // a protected node, the rest public: the site's host, after the check
	SurfaceApp    = "app"    // an internal or private node, the rest public: the app host, after the check
)

// ErrMixedLevels is a chain that holds a protected node and an internal or
// private one: nobody could prove both.
var ErrMixedLevels = errors.New("site: a protected node cannot be above or below an internal or private one")

// SurfaceOf says where the last node of chain is read, or ErrMixedLevels.
func SurfaceOf(chain []Doc) (string, error) {
	protected, member := false, false
	for _, d := range chain {
		switch d.Visibility {
		case Protected:
			protected = true
		case Internal, Private:
			member = true
		}
	}
	switch {
	case protected && member:
		return "", ErrMixedLevels
	case protected:
		return SurfaceSite, nil
	case member:
		return SurfaceApp, nil
	}
	return SurfacePublic, nil
}

// mixedUnder checks a change to one node against the whole tree: the node as
// it would be (its level, its parent), every folder above it, and everything
// under it. all are the site's nodes; next replaces the one of its ID.
func mixedUnder(all []Doc, next Doc) error {
	byID := make(map[int64]Doc, len(all)+1)
	for _, d := range all {
		byID[d.ID] = d
	}
	byID[next.ID] = next
	// kinds of a node's chain, from the node up; through says whether the
	// chain passes through next.
	kinds := func(d Doc) (protected, member, through bool) {
		for depth := 0; depth <= MaxDepth+2; depth++ {
			switch d.Visibility {
			case Protected:
				protected = true
			case Internal, Private:
				member = true
			}
			if d.ID == next.ID {
				through = true
			}
			up, ok := byID[d.Parent]
			if !ok {
				return
			}
			d = up
		}
		return
	}
	for _, d := range byID {
		if p, m, through := kinds(d); through && p && m {
			return ErrMixedLevels
		}
	}
	return nil
}
