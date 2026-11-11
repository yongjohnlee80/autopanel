package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
)

// engines are the stores each test runs on: SQLite always, PostgreSQL when
// AUTOPANEL_TEST_POSTGRES_DSN names a disposable, empty schema.
func engines(t *testing.T) map[string]*Store {
	t.Helper()
	ctx := context.Background()
	out := map[string]*Store{}
	s, err := Open(ctx, Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	out[dao.DialectSQLite] = s
	if dsn := os.Getenv("AUTOPANEL_TEST_POSTGRES_DSN"); dsn != "" {
		p, err := Open(ctx, Config{Engine: dao.DialectPostgres, DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		clear := func() {
			for _, table := range []string{"route", "audit", "cert_blob", "store_lease"} {
				_, _ = p.conn.ExecContext(ctx, "DELETE FROM "+table)
			}
		}
		clear() // the schema is shared with other packages' tests: start empty
		t.Cleanup(func() { clear(); _ = p.Close() })
		out[dao.DialectPostgres] = p
	}
	return out
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	rows, err := s.conn.QueryContext(context.Background(), "SELECT COUNT(*) FROM "+table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	rows.Next()
	if err := rows.Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRoutesWriteWithTheirAuditEntry(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := audit.WithActor(context.Background(), "local:1000")
			rs := s.Routes()
			a, err := rs.Add(ctx, gate.Route{Host: "example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:8080"})
			if err != nil || a.ID == 0 {
				t.Fatalf("Add = %+v, %v", a, err)
			}
			if _, err := rs.Add(ctx, gate.Route{Host: "example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:9"}); !errors.Is(err, gate.ErrDuplicate) {
				t.Fatalf("a duplicate Add = %v; want gate.ErrDuplicate", err)
			}
			if n := count(t, s, "audit"); n != 1 {
				t.Fatalf("audit has %d rows after one add and one refused add; want 1 (the refused one rolled back)", n)
			}
			u, err := rs.Update(ctx, gate.Route{ID: a.ID, Host: "example.com", PathPrefix: "/api", Upstream: "http://127.0.0.1:8081"})
			if err != nil || u.PathPrefix != "/api" {
				t.Fatalf("Update = %+v, %v", u, err)
			}
			if _, err := rs.Update(ctx, gate.Route{ID: 999, Host: "example.com", PathPrefix: "/", Upstream: "http://127.0.0.1"}); !errors.Is(err, gate.ErrNotFound) {
				t.Fatalf("Update of a missing route = %v; want gate.ErrNotFound", err)
			}
			all, err := rs.All(ctx)
			if err != nil || len(all) != 1 || all[0] != u {
				t.Fatalf("All = %+v, %v; want [%+v]", all, err, u)
			}
			if _, err := rs.Remove(ctx, a.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := rs.Remove(ctx, a.ID); !errors.Is(err, gate.ErrNotFound) {
				t.Fatalf("a second Remove = %v; want gate.ErrNotFound", err)
			}
			if n := count(t, s, "audit"); n != 3 {
				t.Fatalf("audit has %d rows; want 3 (add, update, remove)", n)
			}
		})
	}
}

func TestOneAutoPanelHoldsTheStore(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_800_000_000, 0)
			s.now = func() time.Time { return now }
			if err := s.Lease(ctx, "a"); err != nil {
				t.Fatal(err)
			}
			if err := s.Lease(ctx, "a"); err != nil {
				t.Fatalf("the holder must be able to take its own lease again: %v", err)
			}
			if err := s.Lease(ctx, "b"); !errors.Is(err, ErrLeased) {
				t.Fatalf("a second AutoPanel took a live lease: %v", err)
			}
			now = now.Add(LeaseTTL - time.Second)
			if err := s.Renew(ctx, "a"); err != nil {
				t.Fatal(err)
			}
			now = now.Add(LeaseTTL + time.Second)
			if err := s.Lease(ctx, "b"); err != nil {
				t.Fatalf("a lapsed lease must pass to a new holder: %v", err)
			}
			if err := s.Renew(ctx, "a"); !errors.Is(err, ErrLeased) {
				t.Fatalf("the old holder renewed a lease it lost: %v", err)
			}
			if err := s.Release(ctx, "b"); err != nil {
				t.Fatal(err)
			}
			if err := s.Lease(ctx, "a"); err != nil {
				t.Fatalf("a released store must be free: %v", err)
			}
		})
	}
}

func TestBlobsKeepCertMagicsFileSemantics(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			b := s.Blobs()
			for _, k := range []string{"certs/ca/a.example/a.crt", "certs/ca/a.example/a.key", "certs/ca/ab.example/ab.crt", "certs/ca/a_b%/x"} {
				if err := b.Put(ctx, k, []byte(k)); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.Put(ctx, "certs/ca/a.example/a.key", []byte("new")); err != nil {
				t.Fatal(err)
			}
			if v, err := b.Get(ctx, "certs/ca/a.example/a.key"); err != nil || string(v) != "new" {
				t.Fatalf("Get after an overwrite = %q, %v", v, err)
			}
			if _, err := b.Get(ctx, "certs/ca/none"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Get of a missing key = %v; want fs.ErrNotExist", err)
			}
			if st, err := b.Stat(ctx, "certs/ca/a.example"); err != nil || st.IsTerminal {
				t.Errorf("Stat of a directory = %+v, %v", st, err)
			}
			if st, err := b.Stat(ctx, "certs/ca/a.example/a.key"); err != nil || !st.IsTerminal || st.Size != 3 {
				t.Errorf("Stat of a file = %+v, %v", st, err)
			}
			if _, err := b.Stat(ctx, "certs/ca/a.ex"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Stat of a partial component = %v; want fs.ErrNotExist", err)
			}
			if got, _ := b.List(ctx, "certs/ca", false); !slices.Equal(got, []string{"certs/ca/a.example", "certs/ca/a_b%", "certs/ca/ab.example"}) {
				t.Errorf("List = %v", got)
			}
			if got, _ := b.List(ctx, "certs/ca/a.example", true); !slices.Equal(got, []string{"certs/ca/a.example/a.crt", "certs/ca/a.example/a.key"}) {
				t.Errorf("List(recursive) = %v", got)
			}
			if err := b.Delete(ctx, "certs/ca/a.example"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Get(ctx, "certs/ca/a.example/a.crt"); !errors.Is(err, fs.ErrNotExist) {
				t.Error("Delete of a directory left a key under it")
			}
			if _, err := b.Get(ctx, "certs/ca/ab.example/ab.crt"); err != nil {
				t.Error("Delete of a directory removed a sibling that only shares a prefix")
			}
			if err := b.Delete(ctx, "certs/ca/missing"); err != nil {
				t.Errorf("Delete of a missing key = %v; want nil", err)
			}
		})
	}
}
