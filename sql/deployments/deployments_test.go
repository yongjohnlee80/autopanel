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
	"strings"
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
		"000001_update_initialize_tables.sql":   "50801c47a5435790462bb43ef2d70475f72f080306b6ef728d81b3b54e21d333", // v0.1.0
		"000002_update_services.sql":            "65908f8fa102b99396452c8fb154fc958e4cbb68482bad45953cc97ddd53c7c7", // v0.2.2
		"000002_revert_services.sql":            "e936ea57cfe85dd6d7b4cbb67adf7515ae6c17d2f6dbf0e5ebbd0bc3293d8cee", // v0.2.2
		"000003_update_stacks.sql":              "bb28b720c35ad1ed4a9eda337ef37b5697911349e52d412c447461699c5f9590", // v0.2.3
		"000003_revert_stacks.sql":              "103a64e2539b09af598443963b3d82ceff59b1e9d07dc37c8f9c92e5b18d0ee6", // v0.2.3
		"000004_update_domains_and_sources.sql": "0a8364d8d0c715dcc4bc6e7b63f7d0729f450115d805e30be4d48974588a7e4c", // v0.2.4
		"000004_revert_domains_and_sources.sql": "a6412e9bbd8449189987d39394c048ff66196d1a7e1fbfb91711fb0ed02bc4cb", // v0.2.4
		"000005_update_mail.sql":                "f5c6433873bf6e1fb55e2d30436aeb6b9c433488e5094f169de00f595c197ac7", // v0.2.5
		"000005_revert_mail.sql":                "0239f75ab767daddd50989dc3a3b0cfa0b2d22d21436e41166eea1da7517c3e4", // v0.2.5
		"000006_update_users_and_tokens.sql":    "5155eebabab4eea8375b1b4057d765ab790e2a9671de94ae0184d8c59fd1d2ea", // v0.2.6
		"000006_revert_users_and_tokens.sql":    "fff709b3d92cd14169a35161c2e45919e40393b5cc539ca57f22d4857159b4c9", // v0.2.6
	},
	dao.DialectPostgres: {
		"000001_update_initialize_tables.sql":   "c6ba5f47590ab15655f6c4be17ccce0d0b617678d83d58a241c9d015736f41e7", // v0.1.0
		"000002_update_services.sql":            "3cf75898ae3e63188de424366fecc3c16f5d17962c1df4079737f15c0ccde6ff", // v0.2.2
		"000002_revert_services.sql":            "e936ea57cfe85dd6d7b4cbb67adf7515ae6c17d2f6dbf0e5ebbd0bc3293d8cee", // v0.2.2
		"000003_update_stacks.sql":              "f8775991ce9e36392beb7c41e8b9d93225b813c1cc13503242c27b02e9ffe4d7", // v0.2.3
		"000003_revert_stacks.sql":              "103a64e2539b09af598443963b3d82ceff59b1e9d07dc37c8f9c92e5b18d0ee6", // v0.2.3
		"000004_update_domains_and_sources.sql": "b74983a9b59a4413718445c96891db9c23c5c084bdbffe0511ca9f3676537130", // v0.2.4
		"000004_revert_domains_and_sources.sql": "a6412e9bbd8449189987d39394c048ff66196d1a7e1fbfb91711fb0ed02bc4cb", // v0.2.4
		"000005_update_mail.sql":                "b5b57e65063d35c6ed7b52aa4cc4440eee8d561f3e76e2c09fafd7b9b6669fd0", // v0.2.5
		"000005_revert_mail.sql":                "0239f75ab767daddd50989dc3a3b0cfa0b2d22d21436e41166eea1da7517c3e4", // v0.2.5
		"000006_update_users_and_tokens.sql":    "4829a9db84610055c9b0a26c134bd68499f1c9d276348abbe0b94478d1dbfcbd", // v0.2.6
		"000006_revert_users_and_tokens.sql":    "fff709b3d92cd14169a35161c2e45919e40393b5cc539ca57f22d4857159b4c9", // v0.2.6
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
	// 000005: one mail server; its host and its domains are lower case; a
	// record and a DKIM key are kept once per name.
	if err := exec("INSERT INTO mail(id, host, created_at) VALUES (1, 'mail.example.org', 0)"); err != nil {
		t.Fatal(err)
	}
	for what, q := range map[string]string{ // checked here: the tables are emptied by the revert below
		"a second mail server":               "INSERT INTO mail(id, host, created_at) VALUES (2, 'mx.example.org', 0)",
		"a mail host that is not lower case": "UPDATE mail SET host = 'Mail.example.org'",
	} {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
	if err := exec("INSERT INTO mail_domain(name, created_at) VALUES ('example.org', 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO mail_domain(name, created_at) VALUES ('example.org', 0)"); err == nil {
		t.Error("the store accepted a mail domain twice")
	}
	if err := exec("INSERT INTO mail_record(domain, name, type, value, remote_id, updated_at) VALUES ('example.org', 'example.org', 'MX', '10 mail.example.org.', 'r1', 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO mail_record(domain, name, type, value, remote_id, updated_at) VALUES ('example.org', 'example.org', 'MX', 'x', 'r2', 0)"); err == nil {
		t.Error("the store accepted a record twice")
	}
	if err := exec("INSERT INTO mail_dkim(domain, selector, step, since) VALUES ('example.org', 'ap202611e', 'created', 0)"); err != nil {
		t.Fatal(err)
	}
	// 000006: users with roles (the existing root an admin), their factors,
	// recovery codes and tokens; a token's role is a role.
	if err := exec("INSERT INTO app_user(name, created_at) VALUES ('root', 0)"); err != nil {
		t.Fatal(err)
	}
	rows, err = db.QueryContext(ctx, "SELECT role, verifier, must_change, totp FROM app_user WHERE name = 'root'")
	if err != nil {
		t.Fatal(err)
	}
	var role, verifier string
	var mustChange, totp int64
	if !rows.Next() {
		t.Fatal("root's row is not there")
	}
	if err := rows.Scan(&role, &verifier, &mustChange, &totp); err != nil || role != "admin" || verifier != "" || mustChange != 0 || totp != 0 {
		t.Fatalf("an existing user after 000006 = %q, %q, %d, %d, %v; want an admin as it was", role, verifier, mustChange, totp, err)
	}
	_ = rows.Close()
	if err := exec("INSERT INTO api_token(user_id, name, hash, role, created_at, expires_at) SELECT id, 'backup', '\\x01', 'viewer', 0, 1 FROM app_user WHERE name = 'root'"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO api_token(user_id, name, hash, role, created_at, expires_at) SELECT id, 'bad', '\\x02', 'god', 0, 1 FROM app_user WHERE name = 'root'"); err == nil {
		t.Error("the store accepted a token of no role")
	}
	if err := exec("INSERT INTO recovery_code(user_id, hash) SELECT id, '\\x03' FROM app_user WHERE name = 'root'"); err != nil {
		t.Fatal(err)
	}
	// 000007: the rules AutoPanel created, each with its owner and state.
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a1', 'mail', '{}', 'open', 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a2', 'stack:chat', '{}', 'opening', 0)"); err != nil {
		t.Fatal(err)
	}
	for what, q := range map[string]string{
		"a rule twice":         "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a1', 'mail', '{}', 'open', 0)",
		"an owner of no kind":  "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a3', 'admin', '{}', 'open', 0)",
		"a stack with no name": "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a4', 'stack:', '{}', 'open', 0)",
		"a state of no kind":   "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a5', 'mail', '{}', 'shut', 0)",
	} {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
	// 000008: forwards, and a forward as the owner of a firewall rule. The
	// rules made before it are as they were.
	if err := exec("INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('game', 'tcp', 25565, 25565, '127.0.0.1:25565', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('f1', 'forward:game', '{}', 'open', 0)"); err != nil {
		t.Fatalf("a forward as a rule's owner: %v", err)
	}
	for what, q := range map[string]string{
		"a forward's name twice":    "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('game', 'tcp', 1000, 1000, '127.0.0.1:1', 0, 0)",
		"a forward of no protocol":  "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('a', 'sctp', 1000, 1000, '127.0.0.1:1', 0, 0)",
		"a range that runs back":    "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('b', 'tcp', 2000, 1000, '127.0.0.1:1', 0, 0)",
		"a port past 65535":         "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('c', 'tcp', 70000, 70000, '127.0.0.1:1', 0, 0)",
		"a forward with no target":  "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('d', 'tcp', 1000, 1000, '', 0, 0)",
		"a name in capitals":        "INSERT INTO forward(name, proto, port_from, port_to, target, created_at, updated_at) VALUES ('Game2', 'tcp', 1000, 1000, '127.0.0.1:1', 0, 0)",
		"a forward with no name":    "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('f2', 'forward:', '{}', 'open', 0)",
		"still an owner of no kind": "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('f3', 'admin', '{}', 'open', 0)",
		"still a state of no kind":  "INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('f4', 'mail', '{}', 'shut', 0)",
	} {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
	// 000009: tunnel agents. An agent is waiting with a token or enrolled
	// with a key, never both and never neither; a key is one agent's.
	key := strings.Repeat("ab", 32)
	if err := exec("INSERT INTO tunnel_agent(name, token_id, token_hash, token_expires, created_at) VALUES ('nas', 't1', 'h1', 10, 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO tunnel_agent(name, pubkey, created_at) VALUES ('home', '" + key + "', 0)"); err != nil {
		t.Fatal(err)
	}
	for what, q := range map[string]string{
		"an agent's name twice":             "INSERT INTO tunnel_agent(name, token_id, created_at) VALUES ('nas', 't2', 0)",
		"a name in capitals":                "INSERT INTO tunnel_agent(name, token_id, created_at) VALUES ('NAS2', 't3', 0)",
		"an agent with no name":             "INSERT INTO tunnel_agent(name, token_id, created_at) VALUES ('', 't4', 0)",
		"an agent with no key and no token": "INSERT INTO tunnel_agent(name, created_at) VALUES ('a', 0)",
		"an agent with a key and a token":   "INSERT INTO tunnel_agent(name, pubkey, token_id, created_at) VALUES ('b', '" + strings.Repeat("cd", 32) + "', 't5', 0)",
		"a key that is no digest":           "INSERT INTO tunnel_agent(name, pubkey, created_at) VALUES ('c', 'abcd', 0)",
		"one key for two agents":            "INSERT INTO tunnel_agent(name, pubkey, created_at) VALUES ('d', '" + key + "', 0)",
		"one token for two agents":          "INSERT INTO tunnel_agent(name, token_id, created_at) VALUES ('e', 't1', 0)",
	} {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
	// 000010: sites, a tree of folders and documents each. A site has one
	// root folder (no parent, no slug, no owner, public); every other node a
	// parent and a slug unique among its siblings. A document is private
	// unless said, active only when public html, its owner a user who cannot
	// be removed while it is theirs; two resources of one document cannot
	// differ only by case; a folder is not removed while it holds anything.
	if err := exec("INSERT INTO site(host, created_at) VALUES ('blog.example.com', 0)"); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO site_node(site_id, kind, slug, visibility, created_at, updated_at) SELECT id, 'folder', '', 'public', 0, 0 FROM site WHERE host = 'blog.example.com'"); err != nil {
		t.Fatalf("a site's root folder: %v", err)
	}
	const root = "(SELECT n.id FROM site_node n JOIN site s ON s.id = n.site_id WHERE s.host = 'blog.example.com' AND n.parent_id IS NULL)"
	node := func(kind, slug, format, more, values string) string {
		return "INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, source, sha256, created_at, updated_at" + more + ") SELECT s.id, " + root + ", '" + kind + "', '" + slug + "', '" + format + "', u.id, 'x', 'h', 0, 0" + values + " FROM site s, app_user u WHERE s.host = 'blog.example.com' AND u.name = 'root'"
	}
	doc := func(slug, more, values string) string { return node("doc", slug, "md", more, values) }
	if err := exec(doc("first", "", "")); err != nil {
		t.Fatalf("the first document: %v", err)
	}
	if err := exec(node("folder", "guides", "", "", "")); err != nil {
		t.Fatalf("a folder: %v", err)
	}
	if err := exec("INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, created_at, updated_at) SELECT s.id, g.id, 'doc', 'first', 'md', u.id, 0, 0 FROM site s, app_user u, site_node g WHERE s.host = 'blog.example.com' AND u.name = 'root' AND g.slug = 'guides'"); err != nil {
		t.Fatalf("one slug in two folders: %v", err)
	}
	rows, err = db.QueryContext(ctx, "SELECT visibility, active, generation, version FROM site_node WHERE slug = 'first' AND kind = 'doc' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var level string
	var activeDoc, generation, version int64
	if !rows.Next() {
		t.Fatal("the document is not there")
	}
	if err := rows.Scan(&level, &activeDoc, &generation, &version); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if level != "private" || activeDoc != 0 || generation != 1 || version != 1 {
		t.Fatalf("a document with nothing said is %s, active %d, generation %d, version %d; want private, 0, 1, 1", level, activeDoc, generation, version)
	}
	const first = "(SELECT MIN(id) FROM site_node WHERE slug = 'first')"
	if err := exec("INSERT INTO site_resource(doc_id, name, name_fold, mime, size, sha256, data) SELECT " + first + ", 'Flow.png', 'flow.png', 'image/png', 1, 'h', 'x'"); err != nil {
		t.Fatalf("a resource: %v", err)
	}
	if err := exec("INSERT INTO site_node_share(node_id, user_id) SELECT " + first + ", u.id FROM app_user u WHERE u.name = 'root'"); err != nil {
		t.Fatalf("a share: %v", err)
	}
	for what, q := range map[string]string{
		"a site's host twice":                     "INSERT INTO site(host, created_at) VALUES ('blog.example.com', 0)",
		"a host in capitals":                      "INSERT INTO site(host, created_at) VALUES ('Blog2.example.com', 0)",
		"a site with no host":                     "INSERT INTO site(host, created_at) VALUES ('', 0)",
		"a content host that is the site's own":   "INSERT INTO site(host, content_host, created_at) VALUES ('a.example.com', 'a.example.com', 0)",
		"a second root folder":                    "INSERT INTO site_node(site_id, kind, slug, visibility, created_at, updated_at) SELECT id, 'folder', '', 'public', 0, 0 FROM site WHERE host = 'blog.example.com'",
		"a root that is a document":               "INSERT INTO site_node(site_id, kind, slug, format, visibility, created_at, updated_at) SELECT id, 'doc', '', 'md', 'public', 0, 0 FROM site WHERE host = 'blog.example.com'",
		"a node with no slug":                     doc("", "", ""),
		"a node of no kind":                       node("page", "ninth", "md", "", ""),
		"a folder with a format":                  node("folder", "tenth", "md", "", ""),
		"a node of no owner":                      "INSERT INTO site_node(site_id, parent_id, kind, slug, format, created_at, updated_at) SELECT s.id, " + root + ", 'doc', 'eleventh', 'md', 0, 0 FROM site s WHERE s.host = 'blog.example.com'",
		"a node in no folder":                     "INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, created_at, updated_at) SELECT s.id, 999999, 'doc', 'twelfth', 'md', u.id, 0, 0 FROM site s, app_user u WHERE s.host = 'blog.example.com' AND u.name = 'root'",
		"a slug twice in one folder":              doc("first", "", ""),
		"a folder and a document of one slug":     node("folder", "first", "", "", ""),
		"a slug in capitals":                      doc("Second", "", ""),
		"a level of no kind":                      doc("third", ", visibility", ", 'secret'"),
		"a format of no kind":                     node("doc", "fourth", "pdf", "", ""),
		"an active document that is private":      doc("fifth", ", active", ", 1"),
		"an active Markdown document":             doc("sixth", ", active, visibility", ", 1, 'public'"),
		"a document of no site":                   "INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, created_at, updated_at) SELECT 999999, " + root + ", 'doc', 'seventh', 'md', u.id, 0, 0 FROM app_user u WHERE u.name = 'root'",
		"a document of no user":                   "INSERT INTO site_node(site_id, parent_id, kind, slug, format, owner_id, created_at, updated_at) SELECT s.id, " + root + ", 'doc', 'eighth', 'md', 999999, 0, 0 FROM site s WHERE s.host = 'blog.example.com'",
		"a resource's name twice but for case":    "INSERT INTO site_resource(doc_id, name, name_fold, mime, size, sha256, data) SELECT " + first + ", 'flow.PNG', 'flow.png', 'image/png', 1, 'h', 'x'",
		"a resource whose folded name is not its": "INSERT INTO site_resource(doc_id, name, name_fold, mime, size, sha256, data) SELECT " + first + ", 'A.png', 'b.png', 'image/png', 1, 'h', 'x'",
		"a share twice":                           "INSERT INTO site_node_share(node_id, user_id) SELECT " + first + ", u.id FROM app_user u WHERE u.name = 'root'",
		"removing a user who owns a document":     "DELETE FROM app_user WHERE name = 'root'",
		"removing a folder that holds something":  "DELETE FROM site_node WHERE slug = 'guides'",
	} {
		if err := exec(q); err == nil {
			t.Errorf("the store accepted %s", what)
		}
	}
	if err := exec(node("doc", "demo", "html", ", visibility, active", ", 'public', 1")); err != nil {
		t.Fatalf("an active public html document: %v", err)
	}
	if err := exec("DELETE FROM site"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"site_node", "site_node_share", "site_resource"} {
		if n, err := countRows(ctx, db, table); err != nil || n != 0 {
			t.Fatalf("%d rows of %s outlived their site: %v", n, table, err)
		}
	}
	if name, err := deployments.Runner().Revert(ctx, db, 10); err != nil {
		t.Fatalf("reverting 000010 = %q, %v", name, err)
	}
	if err := exec("SELECT host FROM site"); err == nil {
		t.Fatal("the site table outlived its revert")
	}
	if name, err := deployments.Runner().Revert(ctx, db, 9); err != nil {
		t.Fatalf("reverting 000009 = %q, %v", name, err)
	}
	if err := exec("SELECT name FROM tunnel_agent"); err == nil {
		t.Fatal("the tunnel_agent table outlived its revert")
	}
	if name, err := deployments.Runner().Revert(ctx, db, 8); err != nil {
		t.Fatalf("reverting 000008 = %q, %v", name, err)
	}
	if err := exec("SELECT name FROM forward"); err == nil {
		t.Fatal("the forward table outlived its revert")
	}
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('f5', 'forward:game', '{}', 'open', 0)"); err == nil {
		t.Fatal("after the revert a forward may still own a rule")
	}
	// The mail and stack rules outlived both the change of the table and its undoing.
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a1', 'mail', '{}', 'open', 0)"); err == nil {
		t.Fatal("mail's rule was lost when the table was made again")
	}
	if err := exec("INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES ('a2', 'stack:chat', '{}', 'open', 0)"); err == nil {
		t.Fatal("a stack's rule was lost when the table was made again")
	}
	if name, err := deployments.Runner().Revert(ctx, db, 7); err != nil {
		t.Fatalf("reverting 000007 = %q, %v", name, err)
	}
	if err := exec("SELECT owner FROM firewall_rule"); err == nil {
		t.Fatal("the firewall_rule table outlived its revert")
	}
	if name, err := deployments.Runner().Revert(ctx, db, 6); err != nil {
		t.Fatalf("reverting 000006 = %q, %v", name, err)
	}
	if err := exec("SELECT role FROM app_user"); err == nil {
		t.Fatal("the role column outlived its revert")
	}
	if err := exec("DELETE FROM app_user"); err != nil {
		t.Fatal(err)
	}
	if name, err := deployments.Runner().Revert(ctx, db, 5); err != nil {
		t.Fatalf("reverting 000005 = %q, %v", name, err)
	}
	if err := exec("SELECT host FROM mail"); err == nil {
		t.Fatal("the mail table outlived its revert")
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
		for _, table := range []string{"route", "audit", "cert_blob", "store_lease", "secret", "keyslot", "recovery_code", "api_token", "app_user", "service", "domain", "stack_source"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+table) // before Apply, the tables may not exist yet
		}
	}
	clear() // the schema is shared with other packages' tests: start and end empty
	t.Cleanup(func() { clear(); _ = db.Close() })
	applyAndCheck(t, db)
}

// countRows is how many rows a table holds.
func countRows(ctx context.Context, db dao.DataConn, table string) (int64, error) {
	rows, err := db.QueryContext(ctx, "SELECT COUNT(*) FROM "+table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		err = rows.Scan(&n)
	}
	return n, err
}
