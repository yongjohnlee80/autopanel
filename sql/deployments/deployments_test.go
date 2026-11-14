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
// changes.
var released = map[string]map[string]string{
	dao.DialectSQLite: {
		"000001_update_initialize_tables.sql": "50801c47a5435790462bb43ef2d70475f72f080306b6ef728d81b3b54e21d333", // v0.1.0
		"000002_update_services.sql":          "65908f8fa102b99396452c8fb154fc958e4cbb68482bad45953cc97ddd53c7c7", // v0.2.2
		"000002_revert_services.sql":          "e936ea57cfe85dd6d7b4cbb67adf7515ae6c17d2f6dbf0e5ebbd0bc3293d8cee", // v0.2.2
		"000003_update_stacks.sql":            "bb28b720c35ad1ed4a9eda337ef37b5697911349e52d412c447461699c5f9590", // v0.2.3
		"000003_revert_stacks.sql":            "103a64e2539b09af598443963b3d82ceff59b1e9d07dc37c8f9c92e5b18d0ee6", // v0.2.3
	},
	dao.DialectPostgres: {
		"000001_update_initialize_tables.sql": "c6ba5f47590ab15655f6c4be17ccce0d0b617678d83d58a241c9d015736f41e7", // v0.1.0
		"000002_update_services.sql":          "3cf75898ae3e63188de424366fecc3c16f5d17962c1df4079737f15c0ccde6ff", // v0.2.2
		"000002_revert_services.sql":          "e936ea57cfe85dd6d7b4cbb67adf7515ae6c17d2f6dbf0e5ebbd0bc3293d8cee", // v0.2.2
		"000003_update_stacks.sql":            "f8775991ce9e36392beb7c41e8b9d93225b813c1cc13503242c27b02e9ffe4d7", // v0.2.3
		"000003_revert_stacks.sql":            "103a64e2539b09af598443963b3d82ceff59b1e9d07dc37c8f9c92e5b18d0ee6", // v0.2.3
	},
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
	// 000002: a service's name is lower case and unique, and its state is one of three.
	if err := exec("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('turn', 'turn', '{}', 'deploying', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	refused["a second service of one name"] = "INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('turn', 'turn', '{}', 'deployed', 0, 0)"
	refused["a service name that is not lower case"] = "INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('Mail', 'turn', '{}', 'deployed', 0, 0)"
	refused["a state that is none"] = "INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('mail', 'turn', '{}', 'running', 0, 0)"
	if err := exec("INSERT INTO audit(at, actor, action, subject, outcome) VALUES (0, 'root', 'services.deploy', 'turn', 'attempt')"); err != nil {
		t.Fatal(err)
	}
	// 000003: a stack's row keeps what was applied, and starts with none of it.
	if err := exec("UPDATE service SET applied = '{}', applied_at = 1, stopped = '[\"web\"]', pending = '{}' WHERE name = 'turn'"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('blog', '', '{}', 'deploying', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, "SELECT applied, applied_at, stopped, pending FROM service WHERE name = 'blog'")
	if err != nil {
		t.Fatal(err)
	}
	var applied, stopped, pending string
	var at int64
	if !rows.Next() {
		t.Fatal("the new stack's row is not there")
	}
	if err := rows.Scan(&applied, &at, &stopped, &pending); err != nil || applied != "" || at != 0 || stopped != "[]" || pending != "" {
		t.Fatalf("a new stack's row = %q, %d, %q, %q, %v; want nothing applied, stopped or pending", applied, at, stopped, pending, err)
	}
	_ = rows.Close()
	// 000004: every route's host became a domain; a domain is lower case and
	// unique; a stack's source is kept by its name.
	if err := exec("INSERT INTO domain(name, created_at) VALUES ('example.org', 0)"); err != nil {
		t.Fatal(err)
	}
	refused["a second domain of one name"] = "INSERT INTO domain(name, created_at) VALUES ('example.com', 0)" // after the re-apply, the route's host
	refused["a domain that is not lower case"] = "INSERT INTO domain(name, created_at) VALUES ('Example.net', 0)"
	if err := exec("INSERT INTO stack_source(name, path, imported_at, sha256) VALUES ('blog', '/home/admin/blog', 0, 'aa')"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO stack_source(name, path, imported_at, sha256) VALUES ('blog', '/x', 0, 'bb')"); err == nil {
		t.Error("the store accepted a second source of one stack")
	}
	// Undone in order: 000004, then 000003, then 000002; a row an older
	// AutoPanel wrote is whole after each.
	if name, err := deployments.Runner().Revert(ctx, db, 4); err != nil {
		t.Fatalf("reverting 000004 = %q, %v", name, err)
	}
	if err := exec("SELECT name FROM domain"); err == nil {
		t.Fatal("the domain table outlived its revert")
	}
	if name, err := deployments.Runner().Revert(ctx, db, 3); err != nil {
		t.Fatalf("reverting 000003 = %q, %v", name, err)
	}
	if err := exec("SELECT applied FROM service"); err == nil {
		t.Fatal("the stacks' columns outlived their revert")
	}
	if err := exec("SELECT name, template, options, state FROM service WHERE name = 'turn'"); err != nil {
		t.Fatalf("after the revert, a templated row: %v", err)
	}
	if name, err := deployments.Runner().Revert(ctx, db, 2); err != nil {
		t.Fatalf("reverting 000002 = %q, %v", name, err)
	}
	if err := exec("SELECT name FROM service"); err == nil {
		t.Fatal("the service table outlived its revert")
	}
	if _, err := deployments.Runner().Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Applied again over a store with a route: its host is now a domain.
	rows, err = db.QueryContext(ctx, "SELECT name FROM domain")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	if len(names) != 1 || names[0] != "example.com" {
		t.Fatalf("the domains after 000004 = %v; want the route's host", names)
	}
	if err := exec("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES ('turn', 'turn', '{}', 'deploying', 0, 0)"); err != nil {
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
		for _, table := range []string{"route", "audit", "cert_blob", "store_lease", "secret", "keyslot", "app_user", "service", "domain", "stack_source"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+table) // before Apply, the tables may not exist yet
		}
	}
	clear() // the schema is shared with other packages' tests: start and end empty
	t.Cleanup(func() { clear(); _ = db.Close() })
	applyAndCheck(t, db)
}
