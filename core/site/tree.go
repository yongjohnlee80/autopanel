package site

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// THE TREE — a site is a tree of folders and documents (docs/decisions/site.md,
// "Folders"). A node is found by its path; what a reader may do with it is
// what May allows for it and every folder above it (MayAt). A folder the
// caller may not read is, to them, no folder at all: ErrNotFound.

// walk resolves a folder's path in s, as who may see it: the chain from the
// root to the folder. A part that does not exist, or that who may not read,
// is ErrNotFound; one that is a document is ErrNotAFolder.
func (m *Module) walk(ctx context.Context, who Reader, s Site, path string) ([]Doc, error) {
	parts, err := SplitPath(path)
	if err != nil {
		return nil, err
	}
	root, err := m.store.Root(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	chain := []Doc{root}
	for _, part := range parts {
		next, err := m.store.Child(ctx, chain[len(chain)-1].ID, part)
		if err != nil {
			return nil, err
		}
		chain = append(chain, next)
		if !MayAt(who, ActRead, chain) {
			return nil, ErrNotFound
		}
		if !next.IsFolder() {
			return nil, ErrNotAFolder
		}
	}
	return chain, nil
}

// folderFor is the folder a node is put into: path's chain. With parents,
// the folders that do not exist are made, private and the caller's, each in
// one the caller may put things into; a folder that exists and is not theirs
// to put into refuses the call, and nothing is made (F3 of tifa's review).
func (m *Module) folderFor(ctx context.Context, who Reader, me Person, s Site, path string, parents bool) ([]Doc, error) {
	if !parents {
		return m.walk(ctx, who, s, path)
	}
	parts, err := SplitPath(path)
	if err != nil {
		return nil, err
	}
	root, err := m.store.Root(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	chain := []Doc{root}
	for _, part := range parts {
		next, err := m.store.Child(ctx, chain[len(chain)-1].ID, part)
		switch {
		case errors.Is(err, ErrNotFound):
			if !MayPutIn(who, chain) {
				return nil, ErrNotYours
			}
			f := Doc{Site: s.ID, Parent: chain[len(chain)-1].ID, Kind: KindFolder, Slug: part, Owner: me.ID, Visibility: Private}
			if err := f.Check(); err != nil {
				return nil, err
			}
			if next, err = m.store.Create(ctx, f, Source{Body: []byte{}}); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		}
		chain = append(chain, next)
		if !MayAt(who, ActRead, chain) {
			return nil, ErrNotFound
		}
		if !next.IsFolder() {
			return nil, ErrNotAFolder
		}
	}
	return chain, nil
}

// node is the node at path, as who may know of it: its chain. One who may
// not know it exists is ErrNotFound.
func (m *Module) node(ctx context.Context, who Reader, s Site, path string) ([]Doc, error) {
	parts, err := SplitPath(path)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, ErrRoot
	}
	folder, err := m.walk(ctx, who, s, strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return nil, err
	}
	d, err := m.store.Child(ctx, folder[len(folder)-1].ID, parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	chain := append(folder, d)
	if !MayAt(who, ActExists, chain) {
		return nil, ErrNotFound
	}
	return chain, nil
}

// --- folders -------------------------------------------------------------------

// FolderAsk names a folder by its path, and what to make it or change it to.
type FolderAsk struct {
	Site       string    `json:"site"`
	Path       string    `json:"path"`
	Title      *string   `json:"title,omitempty"`
	Visibility string    `json:"visibility,omitempty"`
	Share      *[]string `json:"share,omitempty"`
	Order      *int      `json:"order,omitempty"`
	Parents    bool      `json:"parents,omitempty"` // site.folder.add: make the folders above it that are missing
}

// NodeAsk names a node by its path; To is the folder site.node.move puts it in.
type NodeAsk struct {
	Site string `json:"site"`
	Path string `json:"path"`
	To   string `json:"to,omitempty"`
}

// NodeView is a folder or a document in a list, or as a verb changed it.
type NodeView struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Title      string `json:"title,omitempty"`
	Format     string `json:"format,omitempty"`
	Visibility string `json:"visibility"`
	Owner      string `json:"owner,omitempty"`
	Order      int    `json:"order,omitempty"`
	Version    int64  `json:"version,omitempty"`
	Build      int64  `json:"build,omitempty"`
}

const maxFolderTitle = 200

func folderMeta(title string) (string, error) {
	if len([]rune(title)) > maxFolderTitle || strings.ContainsAny(title, "\n\r") {
		return "", ErrBadMeta
	}
	if title == "" {
		return "", nil
	}
	b, err := json.Marshal(map[string]string{"title": title})
	return string(b), err
}

func titleOf(meta string) string {
	var m struct {
		Title string `json:"title"`
	}
	_ = json.Unmarshal([]byte(meta), &m)
	return m.Title
}

func (m *Module) view(ctx context.Context, chain []Doc, meta string) NodeView {
	d := chain[len(chain)-1]
	v := NodeView{Path: pathOfChain(chain), Kind: d.Kind, Format: d.Format, Visibility: d.Visibility, Order: d.Order, Title: titleOf(meta)}
	if d.Owner != 0 {
		v.Owner = m.people.Name(ctx, d.Owner)
	}
	if d.Kind == KindDoc {
		v.Version = d.Version
	}
	return v
}

func pathOfChain(chain []Doc) string {
	parts := make([]string, 0, len(chain))
	for _, d := range chain {
		if !d.IsRoot() {
			parts = append(parts, d.Slug)
		}
	}
	return strings.Join(parts, "/")
}

func (m *Module) folderAdd(ctx context.Context, p FolderAsk) (NodeView, error) {
	who, me, err := m.reader(ctx)
	if err != nil {
		return NodeView{}, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return NodeView{}, err
	}
	parts, err := SplitPath(p.Path)
	if err != nil {
		return NodeView{}, err
	}
	if len(parts) == 0 {
		return NodeView{}, ErrRoot
	}
	parent, err := m.folderFor(ctx, who, me, s, strings.Join(parts[:len(parts)-1], "/"), p.Parents)
	if err != nil {
		return NodeView{}, err
	}
	if !MayPutIn(who, parent) {
		return NodeView{}, ErrNotYours
	}
	level, err := Level(p.Visibility, nil)
	if err != nil {
		return NodeView{}, err
	}
	var shared []int64
	if p.Share != nil {
		if shared, err = m.share(ctx, *p.Share); err != nil {
			return NodeView{}, err
		}
	}
	meta := ""
	if p.Title != nil {
		if meta, err = folderMeta(*p.Title); err != nil {
			return NodeView{}, err
		}
	}
	f := Doc{Site: s.ID, Parent: parent[len(parent)-1].ID, Kind: KindFolder, Slug: parts[len(parts)-1], Owner: me.ID, Visibility: level, Share: shared}
	if p.Order != nil {
		f.Order = *p.Order
	}
	if err := f.Check(); err != nil {
		return NodeView{}, err
	}
	f, err = m.store.Create(ctx, f, Source{Meta: meta, Body: []byte{}})
	if err != nil {
		return NodeView{}, err
	}
	chain := append(parent, f)
	v := m.view(ctx, chain, meta)
	if PublicAt(chain) {
		if v.Build, err = m.changed(ctx, s, false); err != nil {
			return v, err
		}
	}
	return v, nil
}

func (m *Module) folderSet(ctx context.Context, p FolderAsk) (NodeView, error) {
	who, me, err := m.reader(ctx)
	if err != nil {
		return NodeView{}, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return NodeView{}, err
	}
	chain, err := m.node(ctx, who, s, p.Path)
	if err != nil {
		return NodeView{}, err
	}
	old := chain[len(chain)-1]
	if !old.IsFolder() {
		return NodeView{}, ErrNotAFolder
	}
	if !MayAt(who, ActChange, chain) {
		return NodeView{}, ErrNotYours
	}
	var shared []int64
	if p.Share != nil {
		if shared, err = m.share(ctx, *p.Share); err != nil {
			return NodeView{}, err
		}
	}
	src, err := m.store.Source(ctx, old.ID)
	if err != nil {
		return NodeView{}, err
	}
	meta := src.Meta
	if p.Title != nil {
		if meta, err = folderMeta(*p.Title); err != nil {
			return NodeView{}, err
		}
	}
	d, lowered, err := m.store.Update(ctx, old.ID, func(cur Doc) (Doc, *Source, error) {
		if cur.Owner != me.ID {
			return Doc{}, nil, ErrNotYours
		}
		level, err := Level(p.Visibility, &cur)
		if err != nil {
			return Doc{}, nil, err
		}
		next := cur
		next.Visibility = level
		if p.Order != nil {
			next.Order = *p.Order
		}
		if p.Share != nil {
			next.Share = shared
		} else if level != Private {
			next.Share = nil
		}
		if err := next.Check(); err != nil {
			return Doc{}, nil, err
		}
		return next, &Source{Meta: meta, Body: []byte{}}, nil
	})
	if err != nil {
		return NodeView{}, err
	}
	above := chain[:len(chain)-1]
	chain = append(append([]Doc{}, above...), d)
	v := m.view(ctx, chain, meta)
	withdrawn := lowered && PublicAt(above)
	if withdrawn || PublicAt(chain) {
		if v.Build, err = m.changed(ctx, s, withdrawn); err != nil {
			return v, err
		}
	}
	return v, nil
}

func (m *Module) folderRemove(ctx context.Context, p FolderAsk) (struct{}, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return struct{}{}, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return struct{}{}, err
	}
	chain, err := m.node(ctx, who, s, p.Path)
	if err != nil {
		return struct{}{}, err
	}
	f := chain[len(chain)-1]
	if !f.IsFolder() {
		return struct{}{}, ErrNotAFolder
	}
	if !MayAt(who, ActRemove, chain) {
		return struct{}{}, ErrNotYours
	}
	if _, err := m.store.Remove(ctx, f.ID); err != nil {
		return struct{}{}, err
	}
	if PublicAt(chain) {
		_, err = m.changed(ctx, s, true)
	}
	return struct{}{}, err
}

// nodeList answers the folder's children the caller may see listed.
func (m *Module) nodeList(ctx context.Context, p NodeAsk) ([]NodeView, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return nil, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return nil, err
	}
	folder, err := m.walk(ctx, who, s, p.Path)
	if err != nil {
		return nil, err
	}
	kids, err := m.store.Children(ctx, folder[len(folder)-1].ID)
	if err != nil {
		return nil, err
	}
	out := []NodeView{}
	for _, k := range kids {
		chain := append(append([]Doc{}, folder...), k)
		if !MayAt(who, ActList, chain) {
			continue
		}
		meta := ""
		if k.IsFolder() {
			if src, err := m.store.Source(ctx, k.ID); err == nil {
				meta = src.Meta
			}
		}
		out = append(out, m.view(ctx, chain, meta))
	}
	return out, nil
}

// nodeMove puts a folder or a document, its owner's, into a folder they may
// put things into. Its address changes, and its descendants'. When anything
// public in effect stops being so, the public pages are taken down before it
// answers.
func (m *Module) nodeMove(ctx context.Context, p NodeAsk) (NodeView, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return NodeView{}, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return NodeView{}, err
	}
	chain, err := m.node(ctx, who, s, p.Path)
	if err != nil {
		return NodeView{}, err
	}
	n := chain[len(chain)-1]
	if !MayAt(who, ActChange, chain) {
		return NodeView{}, ErrNotYours
	}
	to, err := m.walk(ctx, who, s, p.To)
	if err != nil {
		return NodeView{}, err
	}
	if !MayPutIn(who, to) {
		return NodeView{}, ErrNotYours
	}
	wasPublic := PublicAt(chain)
	d, lowered, err := m.store.Move(ctx, n.ID, to[len(to)-1].ID)
	if err != nil {
		return NodeView{}, err
	}
	moved := append(append([]Doc{}, to...), d)
	meta := ""
	if d.IsFolder() {
		if src, err := m.store.Source(ctx, d.ID); err == nil {
			meta = src.Meta
		}
	}
	v := m.view(ctx, moved, meta)
	if lowered || wasPublic || PublicAt(moved) {
		if v.Build, err = m.changed(ctx, s, lowered); err != nil {
			return v, err
		}
	}
	return v, nil
}
