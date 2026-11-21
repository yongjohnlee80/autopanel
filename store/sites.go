package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/site"
)

// Sites is the site's Store on the store.
func (s *Store) Sites() site.Store { return sites{s} }

type sites struct{ s *Store }

const (
	siteCols = "id, host, content_host, config, security_gen, created_at, build, live_build, build_state, build_error, built_at, down"
	docCols  = "id, site_id, COALESCE(parent_id, 0), kind, slug, format, COALESCE(owner_id, 0), visibility, ord, active, generation, version"
)

func scanSite(rows dao.Rows) (site.Site, error) {
	var v site.Site
	var down int64
	err := rows.Scan(&v.ID, &v.Host, &v.ContentHost, &v.Config, &v.SecurityGen, &v.CreatedAt,
		&v.Build, &v.LiveBuild, &v.BuildState, &v.BuildError, &v.BuiltAt, &down)
	v.Down = down != 0
	return v, err
}

func scanDoc(rows dao.Rows) (site.Doc, error) {
	var d site.Doc
	var active int64
	err := rows.Scan(&d.ID, &d.Site, &d.Parent, &d.Kind, &d.Slug, &d.Format, &d.Owner, &d.Visibility, &d.Order, &active, &d.Generation, &d.Version)
	d.Active = active != 0
	return d, err
}

// querier is what a read needs: the connection, or a transaction.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (dao.Rows, error)
}

func (ss sites) audit(ctx context.Context, tx dao.TxConn, action, subject, detail string) error {
	_, err := tx.ExecContext(ctx, ss.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)"),
		ss.s.now().Unix(), audit.Actor(ctx), action, subject, detail)
	return err
}

// AddSite inserts the site and its audit entry.
func (ss sites) AddSite(ctx context.Context, v site.Site) (out site.Site, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		rows, err := tx.QueryContext(ctx, ss.s.q("INSERT INTO site(host, content_host, config, created_at) VALUES (?, ?, ?, ?) RETURNING "+siteCols),
			v.Host, v.ContentHost, v.Config, v.CreatedAt)
		if err != nil {
			if errors.Is(ss.s.translate(err), dao.ErrDuplicate) {
				return site.ErrSiteExists
			}
			return err
		}
		if !rows.Next() {
			err := rows.Err()
			_ = rows.Close()
			if err != nil && errors.Is(ss.s.translate(err), dao.ErrDuplicate) {
				return site.ErrSiteExists
			}
			if err == nil {
				err = site.ErrNoSite
			}
			return err
		}
		if out, err = scanSite(rows); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		// Its root folder: no parent, no slug, no owner, public.
		if _, err := tx.ExecContext(ctx, ss.s.q("INSERT INTO site_node(site_id, kind, slug, visibility, created_at, updated_at) VALUES (?, 'folder', '', 'public', ?, ?)"),
			out.ID, v.CreatedAt, v.CreatedAt); err != nil {
			return err
		}
		return ss.audit(ctx, tx, "site.add", "site "+out.Host, "")
	})
	return out, err
}

func (ss sites) Sites(ctx context.Context) ([]site.Site, error) {
	rows, err := ss.s.conn.QueryContext(ctx, "SELECT "+siteCols+" FROM site ORDER BY host")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []site.Site
	for rows.Next() {
		v, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (ss sites) oneSite(ctx context.Context, q querier, stmt string, args ...any) (site.Site, error) {
	rows, err := q.QueryContext(ctx, ss.s.q(stmt), args...)
	if err != nil {
		return site.Site{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return site.Site{}, err
		}
		return site.Site{}, site.ErrNoSite
	}
	v, err := scanSite(rows)
	if err != nil {
		return site.Site{}, err
	}
	return v, rows.Close()
}

func (ss sites) SiteByHost(ctx context.Context, host string) (site.Site, error) {
	return ss.oneSite(ctx, ss.s.conn, "SELECT "+siteCols+" FROM site WHERE host = ?", host)
}

// RemoveSite deletes the site; its documents, their share lists and their
// resources go with it.
func (ss sites) RemoveSite(ctx context.Context, id int64) error {
	return ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "DELETE FROM site WHERE id = ? RETURNING "+siteCols, id)
		if err != nil {
			return err
		}
		return ss.audit(ctx, tx, "site.remove", "site "+v.Host, "")
	})
}

// SetSite replaces the configuration and the content host, with the audit
// entry; the entry says what changed, never the configuration's text.
func (ss sites) SetSite(ctx context.Context, id int64, config, contentHost string) (out site.Site, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		old, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", id)
		if err != nil {
			return err
		}
		if out, err = ss.oneSite(ctx, tx, "UPDATE site SET config = ?, content_host = ? WHERE id = ? RETURNING "+siteCols, config, contentHost, id); err != nil {
			return err
		}
		var what []string
		if old.Config != out.Config {
			what = append(what, "configuration")
		}
		if old.ContentHost != out.ContentHost {
			what = append(what, "content host "+quoteOrNone(out.ContentHost))
		}
		if len(what) == 0 {
			what = append(what, "unchanged")
		}
		return ss.audit(ctx, tx, "site.set", "site "+out.Host, strings.Join(what, "; "))
	})
	return out, err
}

func quoteOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// oneDoc reads one document and its share list.
func (ss sites) oneDoc(ctx context.Context, q querier, stmt string, args ...any) (site.Doc, error) {
	rows, err := q.QueryContext(ctx, ss.s.q(stmt), args...)
	if err != nil {
		return site.Doc{}, err
	}
	if !rows.Next() {
		err := rows.Err()
		_ = rows.Close()
		if err != nil {
			return site.Doc{}, err
		}
		return site.Doc{}, site.ErrNotFound
	}
	d, err := scanDoc(rows)
	if err != nil {
		_ = rows.Close()
		return site.Doc{}, err
	}
	if err := rows.Close(); err != nil {
		return site.Doc{}, err
	}
	d.Share, err = ss.share(ctx, q, d.ID)
	return d, err
}

func (ss sites) share(ctx context.Context, q querier, doc int64) ([]int64, error) {
	rows, err := q.QueryContext(ctx, ss.s.q("SELECT user_id FROM site_node_share WHERE node_id = ? ORDER BY user_id"), doc)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var u int64
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Root is the site's root folder.
func (ss sites) Root(ctx context.Context, siteID int64) (site.Doc, error) {
	return ss.oneDoc(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_node WHERE site_id = ? AND parent_id IS NULL", siteID)
}

// Child is the node of that slug in the folder parent.
func (ss sites) Child(ctx context.Context, parent int64, slug string) (site.Doc, error) {
	return ss.oneDoc(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_node WHERE parent_id = ? AND slug = ?", parent, slug)
}

// Children are the nodes of the folder parent, in their order, then by slug.
func (ss sites) Children(ctx context.Context, parent int64) ([]site.Doc, error) {
	return ss.nodes(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_node WHERE parent_id = ? ORDER BY ord, slug", parent)
}

// Chain is the node and every folder above it, the root first.
func (ss sites) Chain(ctx context.Context, id int64) ([]site.Doc, error) {
	return ss.chain(ctx, ss.s.conn, id)
}

func (ss sites) chain(ctx context.Context, q querier, id int64) ([]site.Doc, error) {
	var out []site.Doc
	for id != 0 {
		if len(out) > site.MaxDepth+2 {
			return nil, site.ErrTooDeep // a loop the store's rules forbid; never followed for ever
		}
		d, err := ss.oneDoc(ctx, q, "SELECT "+docCols+" FROM site_node WHERE id = ?", id)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
		id = d.Parent
	}
	slices.Reverse(out)
	return out, nil
}

// nodes reads the rows stmt answers, each with its share list.
func (ss sites) nodes(ctx context.Context, q querier, stmt string, args ...any) ([]site.Doc, error) {
	rows, err := q.QueryContext(ctx, ss.s.q(stmt), args...)
	if err != nil {
		return nil, err
	}
	var out []site.Doc
	for rows.Next() {
		d, err := scanDoc(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Share, err = ss.share(ctx, q, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// pathOf is a chain's address: its slugs below the root, joined by /.
func pathOf(chain []site.Doc) string {
	parts := make([]string, 0, len(chain))
	for _, d := range chain {
		if !d.IsRoot() {
			parts = append(parts, d.Slug)
		}
	}
	return strings.Join(parts, "/")
}

// folderDepth is how many folders below the root a chain's last node is, when
// it is a folder: a document is at its folder's depth.
func folderDepth(chain []site.Doc) int {
	n := 0
	for _, d := range chain {
		if !d.IsRoot() && d.IsFolder() {
			n++
		}
	}
	return n
}

// countChildren is how many nodes the folder holds.
func (ss sites) countChildren(ctx context.Context, q querier, parent int64) (int, error) {
	rows, err := q.QueryContext(ctx, ss.s.q("SELECT COUNT(*) FROM site_node WHERE parent_id = ?"), parent)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	if rows.Next() {
		err = rows.Scan(&n)
	}
	return n, err
}

func (ss sites) DocByID(ctx context.Context, id int64) (site.Doc, error) {
	return ss.oneDoc(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_node WHERE id = ?", id)
}

// Docs are the site's nodes but its root, folders and documents, by id.
func (ss sites) Docs(ctx context.Context, siteID int64) ([]site.Doc, error) {
	return ss.nodes(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_node WHERE site_id = ? AND parent_id IS NOT NULL ORDER BY id", siteID)
}

func (ss sites) Source(ctx context.Context, id int64) (site.Source, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT meta, source, sha256 FROM site_node WHERE id = ?"), id)
	if err != nil {
		return site.Source{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return site.Source{}, err
		}
		return site.Source{}, site.ErrNotFound
	}
	var src site.Source
	if err := rows.Scan(&src.Meta, &src.Body, &src.SHA256); err != nil {
		return site.Source{}, err
	}
	return src, rows.Close()
}

// setShare replaces a document's share list.
func (ss sites) setShare(ctx context.Context, tx dao.TxConn, doc int64, users []int64) error {
	if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_node_share WHERE node_id = ?"), doc); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := tx.ExecContext(ctx, ss.s.q("INSERT INTO site_node_share(node_id, user_id) VALUES (?, ?)"), doc, u); err != nil {
			if t := ss.s.translate(err); errors.Is(t, dao.ErrForeignKey) || errors.Is(t, dao.ErrDuplicate) {
				return site.ErrNoUser
			}
			return err
		}
	}
	return nil
}

func active(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// subject is how the audit log names a node: its kind, its site and its
// path, the path of its folder for one not made yet.
func (ss sites) subject(ctx context.Context, tx dao.TxConn, d site.Doc) (string, error) {
	v, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", d.Site)
	if err != nil {
		return "", err
	}
	where := d.Slug
	if d.Parent != 0 {
		chain, err := ss.chain(ctx, tx, d.Parent)
		if err != nil {
			return "", err
		}
		if p := pathOf(chain); p != "" {
			where = p + "/" + d.Slug
		}
	}
	kind := "document"
	if d.IsFolder() {
		kind = "folder"
	}
	return kind + " " + v.Host + "/" + where, nil
}

// Create inserts the document, its share list and its audit entry.
func (ss sites) Create(ctx context.Context, d site.Doc, src site.Source) (out site.Doc, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		// Its folder: of the same site, a folder, with room, and the new node
		// within the bounds of depth and address.
		chain, err := ss.chain(ctx, tx, d.Parent)
		if err != nil {
			if errors.Is(err, site.ErrNotFound) {
				return site.ErrNotAFolder
			}
			return err
		}
		parent := chain[len(chain)-1]
		if d.Parent == 0 || parent.Site != d.Site || !parent.IsFolder() {
			return site.ErrNotAFolder
		}
		if d.IsFolder() && folderDepth(chain)+1 > site.MaxDepth {
			return site.ErrTooDeep
		}
		if joinedLen(pathOf(chain), d.Slug) > site.MaxPath {
			return site.ErrPathTooLong
		}
		if n, err := ss.countChildren(ctx, tx, d.Parent); err != nil {
			return err
		} else if n >= site.MaxChildren {
			return site.ErrTooManyNodes
		}
		subject, err := ss.subject(ctx, tx, d)
		if err != nil {
			return err
		}
		now := ss.s.now().Unix()
		out, err = ss.oneDoc(ctx, tx, `INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, visibility, ord, active, meta, source, sha256, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING `+docCols,
			d.Site, d.Parent, d.Kind, d.Slug, d.Format, d.Owner, d.Visibility, d.Order, active(d.Active), src.Meta, src.Body, src.SHA256, now, now)
		if err != nil {
			switch t := ss.s.translate(err); {
			case errors.Is(t, dao.ErrDuplicate):
				return site.ErrDuplicate
			case errors.Is(t, dao.ErrForeignKey):
				return site.ErrNoUser
			}
			return err
		}
		if err := ss.setShare(ctx, tx, out.ID, d.Share); err != nil {
			return err
		}
		out.Share = slices.Clone(d.Share)
		slices.Sort(out.Share)
		return ss.audit(ctx, tx, "site."+out.Kind+".create", subject, out.Visibility)
	})
	return out, err
}

// Update changes the document inside one transaction with the read its
// change is decided from.
func (ss sites) Update(ctx context.Context, id int64, change func(old site.Doc) (site.Doc, *site.Source, error)) (out site.Doc, lowered bool, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		old, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_node WHERE id = ?", id)
		if err != nil {
			return err
		}
		subject, err := ss.subject(ctx, tx, old)
		if err != nil {
			return err
		}
		next, src, err := change(old)
		if err != nil {
			return err
		}
		// What is never an update's to change.
		next.ID, next.Site, next.Slug, next.Owner = old.ID, old.Site, old.Slug, old.Owner
		next.Parent, next.Kind = old.Parent, old.Kind
		if old.IsRoot() {
			return site.ErrRoot
		}
		next.Generation, next.Version = old.Generation, old.Version
		wantShare := slices.Clone(next.Share)
		slices.Sort(wantShare)
		if next.Visibility != old.Visibility || !slices.Equal(wantShare, old.Share) {
			next.Generation++
		}
		now := ss.s.now().Unix()
		if src != nil {
			var have string
			rows, err := tx.QueryContext(ctx, ss.s.q("SELECT sha256 FROM site_node WHERE id = ?"), id)
			if err != nil {
				return err
			}
			if rows.Next() {
				err = rows.Scan(&have)
			}
			if cerr := rows.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			if have != src.SHA256 || next.Format != old.Format {
				next.Version++
			}
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site_node SET meta = ?, source = ?, sha256 = ? WHERE id = ?"), src.Meta, src.Body, src.SHA256, id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, ss.s.q(`UPDATE site_node SET format = ?, visibility = ?, ord = ?, active = ?, generation = ?, version = ?, updated_at = ?
			WHERE id = ?`), next.Format, next.Visibility, next.Order, active(next.Active), next.Generation, next.Version, now, id); err != nil {
			return err
		}
		if err := ss.setShare(ctx, tx, id, wantShare); err != nil {
			return err
		}
		next.Share = wantShare
		lowered = site.Lowers(old.Visibility, next.Visibility)
		if lowered {
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site SET security_gen = security_gen + 1 WHERE id = ?"), old.Site); err != nil {
				return err
			}
		}
		out = next
		detail := next.Visibility
		if next.Visibility != old.Visibility {
			detail = old.Visibility + " to " + next.Visibility
		}
		return ss.audit(ctx, tx, "site."+old.Kind+".update", subject, detail)
	})
	return out, lowered, err
}

// Remove deletes the document and records it; a public one's removal raises
// its site's security generation.
func (ss sites) Remove(ctx context.Context, id int64) (out site.Doc, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		old, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_node WHERE id = ?", id)
		if err != nil {
			return err
		}
		if old.IsRoot() {
			return site.ErrRoot
		}
		if n, err := ss.countChildren(ctx, tx, id); err != nil {
			return err
		} else if n > 0 {
			return site.ErrNotEmpty
		}
		subject, err := ss.subject(ctx, tx, old)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_node WHERE id = ?"), id); err != nil {
			return err
		}
		if old.Visibility == site.Public {
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site SET security_gen = security_gen + 1 WHERE id = ?"), old.Site); err != nil {
				return err
			}
		}
		out = old
		return ss.audit(ctx, tx, "site."+old.Kind+".remove", subject, old.Visibility)
	})
	return out, err
}

const resourceCols = "id, doc_id, name, mime, size, sha256"

func scanResource(rows dao.Rows) (site.Resource, error) {
	var r site.Resource
	err := rows.Scan(&r.ID, &r.Doc, &r.Name, &r.MIME, &r.Size, &r.SHA256)
	return r, err
}

// PutResource stores the file and raises its document's version when the
// content is new, in one transaction.
func (ss sites) PutResource(ctx context.Context, doc int64, r site.Resource, data []byte) (out site.Resource, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_node WHERE id = ?", doc); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, ss.s.q("SELECT name, sha256 FROM site_resource WHERE doc_id = ?"), doc)
		if err != nil {
			return err
		}
		n, same, changed := 0, false, true
		for rows.Next() {
			var name, sum string
			if err := rows.Scan(&name, &sum); err != nil {
				_ = rows.Close()
				return err
			}
			n++
			switch {
			case name == r.Name:
				same, changed = true, sum != r.SHA256
			case strings.EqualFold(name, r.Name):
				_ = rows.Close()
				return site.ErrResourceTaken
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if !same && n >= site.MaxResources {
			return site.ErrTooMany
		}
		if same {
			if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_resource WHERE doc_id = ? AND name = ?"), doc, r.Name); err != nil {
				return err
			}
		}
		res, err := tx.QueryContext(ctx, ss.s.q(`INSERT INTO site_resource(doc_id, name, name_fold, mime, size, sha256, data)
			VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING `+resourceCols), doc, r.Name, strings.ToLower(r.Name), r.MIME, int64(len(data)), r.SHA256, data)
		if err != nil {
			if errors.Is(ss.s.translate(err), dao.ErrDuplicate) {
				return site.ErrResourceTaken
			}
			return err
		}
		if !res.Next() {
			err := res.Err()
			_ = res.Close()
			if err != nil && errors.Is(ss.s.translate(err), dao.ErrDuplicate) {
				return site.ErrResourceTaken
			}
			if err == nil {
				err = site.ErrNoResource
			}
			return err
		}
		if out, err = scanResource(res); err != nil {
			_ = res.Close()
			return err
		}
		if err := res.Close(); err != nil {
			return err
		}
		if changed {
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site_node SET version = version + 1, updated_at = ? WHERE id = ?"), ss.s.now().Unix(), doc); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (ss sites) Resources(ctx context.Context, doc int64) ([]site.Resource, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT "+resourceCols+" FROM site_resource WHERE doc_id = ? ORDER BY name"), doc)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []site.Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResourceData reads one file by its exact name.
func (ss sites) ResourceData(ctx context.Context, doc int64, name string) (site.Resource, []byte, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT "+resourceCols+", data FROM site_resource WHERE doc_id = ? AND name = ?"), doc, name)
	if err != nil {
		return site.Resource{}, nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return site.Resource{}, nil, err
		}
		return site.Resource{}, nil, site.ErrNoResource
	}
	var r site.Resource
	var data []byte
	if err := rows.Scan(&r.ID, &r.Doc, &r.Name, &r.MIME, &r.Size, &r.SHA256, &data); err != nil {
		return site.Resource{}, nil, err
	}
	return r, data, rows.Close()
}

// RemoveResource deletes one file and raises its document's version.
func (ss sites) RemoveResource(ctx context.Context, doc int64, name string) error {
	return ss.s.tx(ctx, func(tx dao.TxConn) error {
		res, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_resource WHERE doc_id = ? AND name = ?"), doc, name)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return site.ErrNoResource
		}
		_, err = tx.ExecContext(ctx, ss.s.q("UPDATE site_node SET version = version + 1, updated_at = ? WHERE id = ?"), ss.s.now().Unix(), doc)
		return err
	})
}

// --- builds ----------------------------------------------------------------------

func (ss sites) SiteByID(ctx context.Context, id int64) (site.Site, error) {
	return ss.oneSite(ctx, ss.s.conn, "SELECT "+siteCols+" FROM site WHERE id = ?", id)
}

// AskBuild raises the site's build number; the state is waiting unless a
// build is running, which the new number will follow.
func (ss sites) AskBuild(ctx context.Context, id int64) (n int64, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "UPDATE site SET build = build + 1, build_state = CASE WHEN build_state = 'building' THEN 'building' ELSE 'waiting' END WHERE id = ? RETURNING "+siteCols, id)
		n = v.Build
		return err
	})
	return n, err
}

// StartBuild answers the newest build asked for, with the site's public
// documents and the digests of their sources and resources, read in one
// transaction with the security generation the build will carry.
func (ss sites) StartBuild(ctx context.Context, id int64) (snap site.Snapshot, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", id)
		if err != nil {
			return err
		}
		if v.Build == 0 || (v.LiveBuild >= v.Build && !v.Down) {
			return site.ErrNoBuild
		}
		if v, err = ss.oneSite(ctx, tx, "UPDATE site SET build_state = 'building' WHERE id = ? RETURNING "+siteCols, id); err != nil {
			return err
		}
		snap = site.Snapshot{Site: v, Build: v.Build}
		// Every node, then in Go: a node is in the build when it and every
		// folder above it are public; its path is its slugs.
		rows, err := tx.QueryContext(ctx, ss.s.q("SELECT "+docCols+", meta, sha256 FROM site_node WHERE site_id = ? ORDER BY id"), id)
		if err != nil {
			return err
		}
		type row struct {
			d         site.Doc
			meta, sha string
		}
		all := map[int64]row{}
		var order []int64
		for rows.Next() {
			var r row
			var active int64
			if err := rows.Scan(&r.d.ID, &r.d.Site, &r.d.Parent, &r.d.Kind, &r.d.Slug, &r.d.Format, &r.d.Owner, &r.d.Visibility, &r.d.Order, &active, &r.d.Generation, &r.d.Version, &r.meta, &r.sha); err != nil {
				_ = rows.Close()
				return err
			}
			r.d.Active = active != 0
			all[r.d.ID] = r
			order = append(order, r.d.ID)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		// public and path, memoised from the root down
		type seen struct {
			public bool
			path   string
		}
		memo := map[int64]seen{}
		var walk func(id int64, depth int) seen
		walk = func(id int64, depth int) seen {
			if m, ok := memo[id]; ok {
				return m
			}
			r, ok := all[id]
			if !ok || depth > site.MaxDepth+2 {
				return seen{}
			}
			var m seen
			if r.d.IsRoot() {
				m = seen{public: r.d.Visibility == site.Public}
			} else {
				up := walk(r.d.Parent, depth+1)
				m = seen{public: up.public && r.d.Visibility == site.Public, path: strings.TrimPrefix(up.path+"/"+r.d.Slug, "/")}
			}
			memo[id] = m
			return m
		}
		for _, nid := range order {
			r := all[nid]
			if r.d.IsRoot() {
				continue
			}
			m := walk(nid, 0)
			if !m.public {
				continue
			}
			if r.d.IsFolder() {
				snap.Folders = append(snap.Folders, site.SnapFolder{Doc: r.d, Meta: r.meta, Path: m.path})
				continue
			}
			snap.Docs = append(snap.Docs, site.SnapDoc{Doc: r.d, Meta: r.meta, SHA256: r.sha, Path: m.path})
		}
		for i := range snap.Docs {
			rows, err := tx.QueryContext(ctx, ss.s.q("SELECT "+resourceCols+" FROM site_resource WHERE doc_id = ? ORDER BY name"), snap.Docs[i].Doc.ID)
			if err != nil {
				return err
			}
			for rows.Next() {
				r, err := scanResource(rows)
				if err != nil {
					_ = rows.Close()
					return err
				}
				snap.Docs[i].Resources = append(snap.Docs[i].Resources, r)
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		return nil
	})
	return snap, err
}

// FinishBuild records build n's end. A build that went live is served from
// now on, unless a later one already is; the site is up again. A failed one
// leaves what was served, or leaves the site down if it was. Either way the
// state is waiting when a newer build is owed.
func (ss sites) FinishBuild(ctx context.Context, id, n int64, failure string, at int64) (out site.Site, err error) {
	if len(failure) > 4000 {
		failure = failure[len(failure)-4000:]
	}
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", id)
		if err != nil {
			return err
		}
		live, down, state := v.LiveBuild, v.Down, site.BuildFailed
		if failure == "" {
			live, down, state = max(live, n), false, site.BuildLive
		}
		if v.Build > n {
			state = site.BuildWaiting
		}
		downInt := 0
		if down {
			downInt = 1
		}
		out, err = ss.oneSite(ctx, tx, "UPDATE site SET live_build = ?, down = ?, build_state = ?, build_error = ?, built_at = ? WHERE id = ? RETURNING "+siteCols,
			live, downInt, state, failure, at, id)
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("build %d live", n)
		if failure != "" {
			detail = fmt.Sprintf("build %d failed", n)
		}
		return ss.audit(ctx, tx, "site.build", "site "+out.Host, detail)
	})
	return out, err
}

// TakeDown records that the live pages were taken down: nothing is served
// until a build passes.
func (ss sites) TakeDown(ctx context.Context, id int64) error {
	return ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "UPDATE site SET down = 1 WHERE id = ? RETURNING "+siteCols, id)
		if err != nil {
			return err
		}
		return ss.audit(ctx, tx, "site.down", "site "+v.Host, "something public was withdrawn")
	})
}

// Owed are the sites whose newest build is not live: asked for, running when
// the core stopped, or down.
func (ss sites) Owed(ctx context.Context) ([]site.Site, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT "+siteCols+" FROM site WHERE (build > live_build AND build_state <> 'failed') OR build_state = 'building' OR down = 1 ORDER BY id"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []site.Site
	for rows.Next() {
		v, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// NoteRead audits an administrator's read of a document not theirs.
func (ss sites) NoteRead(ctx context.Context, d site.Doc) error {
	return ss.s.tx(ctx, func(tx dao.TxConn) error {
		v, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", d.Site)
		if err != nil {
			return err
		}
		return ss.audit(ctx, tx, "site.doc.read", fmt.Sprintf("site %s document %s (#%d)", v.Host, d.Slug, d.ID), "read by an administrator; level "+d.Visibility)
	})
}

// Move puts a node into another folder of its site, checked whole in one
// transaction: never into itself or anything under it; every node it carries
// within the bounds of depth and address at its new place; room in the
// folder; and when it stops being public where it was, a withdrawal (the
// site's security generation rises).
func (ss sites) Move(ctx context.Context, id, parent int64) (out site.Doc, lowered bool, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		from, err := ss.chain(ctx, tx, id)
		if err != nil {
			return err
		}
		node := from[len(from)-1]
		if node.IsRoot() {
			return site.ErrRoot
		}
		to, err := ss.chain(ctx, tx, parent)
		if err != nil {
			if errors.Is(err, site.ErrNotFound) {
				return site.ErrNotAFolder
			}
			return err
		}
		dest := to[len(to)-1]
		if dest.Site != node.Site || !dest.IsFolder() {
			return site.ErrNotAFolder
		}
		for _, a := range to {
			if a.ID == id {
				return site.ErrCycle
			}
		}
		if parent == node.Parent {
			out = node
			return nil
		}
		// Every node it carries, at its new place.
		base, baseDepth := pathOf(to), folderDepth(to)
		type item struct {
			id    int64
			kind  string
			rel   string
			depth int
		}
		queue := []item{{node.ID, node.Kind, node.Slug, 0}}
		for len(queue) > 0 {
			it := queue[0]
			queue = queue[1:]
			depth := it.depth
			if it.kind == site.KindFolder {
				depth++
				if baseDepth+depth > site.MaxDepth {
					return site.ErrTooDeep
				}
			}
			if joinedLen(base, it.rel) > site.MaxPath {
				return site.ErrPathTooLong
			}
			if it.kind != site.KindFolder {
				continue
			}
			rows, err := tx.QueryContext(ctx, ss.s.q("SELECT id, kind, slug FROM site_node WHERE parent_id = ?"), it.id)
			if err != nil {
				return err
			}
			for rows.Next() {
				var c item
				if err := rows.Scan(&c.id, &c.kind, &c.rel); err != nil {
					_ = rows.Close()
					return err
				}
				c.rel, c.depth = it.rel+"/"+c.rel, depth
				queue = append(queue, c)
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		if n, err := ss.countChildren(ctx, tx, parent); err != nil {
			return err
		} else if n >= site.MaxChildren {
			return site.ErrTooManyNodes
		}
		subject, err := ss.subject(ctx, tx, node)
		if err != nil {
			return err
		}
		out, err = ss.oneDoc(ctx, tx, "UPDATE site_node SET parent_id = ?, generation = generation + 1, updated_at = ? WHERE id = ? RETURNING "+docCols,
			parent, ss.s.now().Unix(), id)
		if err != nil {
			if errors.Is(ss.s.translate(err), dao.ErrDuplicate) {
				return site.ErrDuplicate
			}
			return err
		}
		lowered = allPublic(from) && !allPublic(append(slices.Clone(to), node))
		if lowered {
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site SET security_gen = security_gen + 1 WHERE id = ?"), node.Site); err != nil {
				return err
			}
		}
		return ss.audit(ctx, tx, "site."+node.Kind+".move", subject, "to /"+base)
	})
	return out, lowered, err
}

// allPublic reports whether every node of a chain is public: whether its last
// node is, in effect.
func allPublic(chain []site.Doc) bool {
	for _, d := range chain {
		if d.Visibility != site.Public {
			return false
		}
	}
	return true
}

// joinedLen is the length of base and rel joined by a slash.
func joinedLen(base, rel string) int {
	if base == "" {
		return len(rel)
	}
	return len(base) + 1 + len(rel)
}
