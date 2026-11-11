package deployments_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/yongjohnlee80/golib/dao"
	"github.com/yongjohnlee80/golib/dao/deploy"
	"github.com/yongjohnlee80/golib/dao/postgres"
	"github.com/yongjohnlee80/golib/dao/sqlite"

	"github.com/yongjohnlee80/autopanel/sql/deployments"
)

// released is every released script's digest, by engine and name. A released
// script NEVER changes: the ledger records the digest it was applied with, and
// an edit under the same name is a schema no store agrees with. A script adds
// its line here when it ships in a tagged release; an existing line never
// changes. Empty until the first tag.
var released = map[string]map[string]string{
	dao.DialectSQLite:   {},
	dao.DialectPostgres: {},
}

func names(t *testing.T, engine string) []string {
	t.Helper()
	entries, err := fs.ReadDir(deployments.FS(), engine)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestEveryEngineNamesTheSameScripts(t *testing.T) {
	want := names(t, deployments.Engines[0])
	for _, engine := range deployments.Engines[1:] {
		got := names(t, engine)
		if len(got) != len(want) {
			t.Fatalf("%s has %d scripts, %s has %d: %v vs %v", engine, len(got), deployments.Engines[0], len(want), got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s names %q where %s names %q", engine, got[i], deployments.Engines[0], want[i])
			}
		}
	}
}

func TestEveryEngineLoads(t *testing.T) {
	for _, engine := range deployments.Engines {
		if _, err := deploy.Load(deployments.FS(), engine); err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
	}
}

func TestReleasedScriptsAreUnchanged(t *testing.T) {
	for engine, scripts := range released {
		for name, want := range scripts {
			b, err := fs.ReadFile(deployments.FS(), path.Join(engine, name))
			if err != nil {
				t.Fatalf("released %s/%s is gone: %v", engine, name, err)
			}
			sum := sha256.Sum256(b)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("released %s/%s changed: digest %s, released %s", engine, name, got, want)
			}
		}
	}
}

func openSQLite(t *testing.T) dao.DataConn {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store.db")
	db, err := sqlite.Open(context.Background(), "file:"+p+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// applyAndCheck applies every script, then checks the constraints the gate and
// the one-instance rule rely on.
func applyAndCheck(t *testing.T, db dao.DataConn) {
	t.Helper()
	ctx := context.Background()
	if _, err := deployments.Runner().Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	st, err := deployments.Runner().Apply(ctx, db)
	if err != nil || len(st.Pending) != 0 || len(st.Applied) == 0 {
		t.Fatalf("a second Apply = %+v, %v; want nothing pending", st, err)
	}
	exec := func(q string, args ...any) error {
		_, err := db.ExecContext(ctx, q, args...)
		return err
	}
	if err := exec("INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES ('example.com', '/', 'http://127.0.0.1:8080', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"a second route for one host and prefix": "INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES ('example.com', '/', 'http://127.0.0.1:9090', 0, 0)",
		"a host that is not lower case":          "INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES ('Example.org', '/', 'http://127.0.0.1:8080', 0, 0)",
		"an empty host":                          "INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES ('', '/', 'http://127.0.0.1:8080', 0, 0)",
		"a prefix without a leading slash":       "INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES ('example.net', 'api', 'http://127.0.0.1:8080', 0, 0)",
		"a second store lease":                   "INSERT INTO store_lease(id, holder, started_at, renewed_at) VALUES (2, 'b', 0, 0)",
	}
	if err := exec("INSERT INTO store_lease(id, holder, started_at, renewed_at) VALUES (1, 'a', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	for what, q := range refused {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
}

func TestTheScriptsApplyOnSQLite(t *testing.T) {
	applyAndCheck(t, openSQLite(t))
}

// TestTheScriptsApplyOnPostgres runs against a disposable PostgreSQL named by
// AUTOPANEL_TEST_POSTGRES_DSN (CI's service container); without it, it skips.
// The DSN must name an empty schema the test may fill.
func TestTheScriptsApplyOnPostgres(t *testing.T) {
	dsn := os.Getenv("AUTOPANEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AUTOPANEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	clear := func() {
		for _, table := range []string{"route", "audit", "cert_blob", "store_lease"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+table) // before Apply, the tables may not exist yet
		}
	}
	clear() // the schema is shared with other packages' tests: start and end empty
	t.Cleanup(func() { clear(); _ = db.Close() })
	applyAndCheck(t, db)
}
