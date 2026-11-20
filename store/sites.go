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
	docCols  = "id, site_id, slug, format, owner_id, visibility, collection, ord, active, generation, version"
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
	err := rows.Scan(&d.ID, &d.Site, &d.Slug, &d.Format, &d.Owner, &d.Visibility, &d.Collection, &d.Order, &active, &d.Generation, &d.Version)
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
	rows, err := q.QueryContext(ctx, ss.s.q("SELECT user_id FROM site_doc_share WHERE doc_id = ? ORDER BY user_id"), doc)
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

func (ss sites) Doc(ctx context.Context, siteID int64, slug string) (site.Doc, error) {
	return ss.oneDoc(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_doc WHERE site_id = ? AND slug = ?", siteID, slug)
}

func (ss sites) DocByID(ctx context.Context, id int64) (site.Doc, error) {
	return ss.oneDoc(ctx, ss.s.conn, "SELECT "+docCols+" FROM site_doc WHERE id = ?", id)
}

func (ss sites) Docs(ctx context.Context, siteID int64) ([]site.Doc, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT "+docCols+" FROM site_doc WHERE site_id = ? ORDER BY slug"), siteID)
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
		if out[i].Share, err = ss.share(ctx, ss.s.conn, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (ss sites) Source(ctx context.Context, id int64) (site.Source, error) {
	rows, err := ss.s.conn.QueryContext(ctx, ss.s.q("SELECT meta, source, sha256 FROM site_doc WHERE id = ?"), id)
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
	if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_doc_share WHERE doc_id = ?"), doc); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := tx.ExecContext(ctx, ss.s.q("INSERT INTO site_doc_share(doc_id, user_id) VALUES (?, ?)"), doc, u); err != nil {
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

// subject is how the audit log names a document: by its site and its slug.
func (ss sites) subject(ctx context.Context, tx dao.TxConn, d site.Doc) (string, error) {
	v, err := ss.oneSite(ctx, tx, "SELECT "+siteCols+" FROM site WHERE id = ?", d.Site)
	if err != nil {
		return "", err
	}
	return "document " + v.Host + "/" + d.Slug, nil
}

// Create inserts the document, its share list and its audit entry.
func (ss sites) Create(ctx context.Context, d site.Doc, src site.Source) (out site.Doc, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		subject, err := ss.subject(ctx, tx, d)
		if err != nil {
			return err
		}
		now := ss.s.now().Unix()
		out, err = ss.oneDoc(ctx, tx, `INSERT INTO site_doc(site_id, slug, format, owner_id, visibility, collection, ord, active, meta, source, sha256, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING `+docCols,
			d.Site, d.Slug, d.Format, d.Owner, d.Visibility, d.Collection, d.Order, active(d.Active), src.Meta, src.Body, src.SHA256, now, now)
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
		return ss.audit(ctx, tx, "site.doc.create", subject, out.Visibility)
	})
	return out, err
}

// Update changes the document inside one transaction with the read its
// change is decided from.
func (ss sites) Update(ctx context.Context, id int64, change func(old site.Doc) (site.Doc, *site.Source, error)) (out site.Doc, lowered bool, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		old, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_doc WHERE id = ?", id)
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
		next.Generation, next.Version = old.Generation, old.Version
		wantShare := slices.Clone(next.Share)
		slices.Sort(wantShare)
		if next.Visibility != old.Visibility || !slices.Equal(wantShare, old.Share) {
			next.Generation++
		}
		now := ss.s.now().Unix()
		if src != nil {
			var have string
			rows, err := tx.QueryContext(ctx, ss.s.q("SELECT sha256 FROM site_doc WHERE id = ?"), id)
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
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site_doc SET meta = ?, source = ?, sha256 = ? WHERE id = ?"), src.Meta, src.Body, src.SHA256, id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, ss.s.q(`UPDATE site_doc SET format = ?, visibility = ?, collection = ?, ord = ?, active = ?, generation = ?, version = ?, updated_at = ?
			WHERE id = ?`), next.Format, next.Visibility, next.Collection, next.Order, active(next.Active), next.Generation, next.Version, now, id); err != nil {
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
		return ss.audit(ctx, tx, "site.doc.update", subject, detail)
	})
	return out, lowered, err
}

// Remove deletes the document and records it; a public one's removal raises
// its site's security generation.
func (ss sites) Remove(ctx context.Context, id int64) (out site.Doc, err error) {
	err = ss.s.tx(ctx, func(tx dao.TxConn) error {
		old, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_doc WHERE id = ?", id)
		if err != nil {
			return err
		}
		subject, err := ss.subject(ctx, tx, old)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM site_doc WHERE id = ?"), id); err != nil {
			return err
		}
		if old.Visibility == site.Public {
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site SET security_gen = security_gen + 1 WHERE id = ?"), old.Site); err != nil {
				return err
			}
		}
		out = old
		return ss.audit(ctx, tx, "site.doc.remove", subject, old.Visibility)
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
		if _, err := ss.oneDoc(ctx, tx, "SELECT "+docCols+" FROM site_doc WHERE id = ?", doc); err != nil {
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
			if _, err := tx.ExecContext(ctx, ss.s.q("UPDATE site_doc SET version = version + 1, updated_at = ? WHERE id = ?"), ss.s.now().Unix(), doc); err != nil {
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
		_, err = tx.ExecContext(ctx, ss.s.q("UPDATE site_doc SET version = version + 1, updated_at = ? WHERE id = ?"), ss.s.now().Unix(), doc)
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
		rows, err := tx.QueryContext(ctx, ss.s.q("SELECT "+docCols+", meta, sha256 FROM site_doc WHERE site_id = ? AND visibility = 'public' ORDER BY slug"), id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var d site.Doc
			var active int64
			var sd site.SnapDoc
			if err := rows.Scan(&d.ID, &d.Site, &d.Slug, &d.Format, &d.Owner, &d.Visibility, &d.Collection, &d.Order, &active, &d.Generation, &d.Version, &sd.Meta, &sd.SHA256); err != nil {
				_ = rows.Close()
				return err
			}
			d.Active = active != 0
			sd.Doc = d
			snap.Docs = append(snap.Docs, sd)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
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
