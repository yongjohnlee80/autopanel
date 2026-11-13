package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

func unlocked(t *testing.T) *keyslot.Vault {
	t.Helper()
	mk, err := keyslot.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &keyslot.Vault{}
	if err := v.Unlock(mk); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBlobsAreSealedAndBoundToTheirKey(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			v := unlocked(t)
			if err := s.Blobs(v).Put(ctx, "certs/a/a.key", []byte("PRIVATE KEY")); err != nil {
				t.Fatal(err)
			}
			rows, err := s.conn.QueryContext(ctx, "SELECT value FROM cert_blob WHERE key = 'certs/a/a.key'")
			if err != nil {
				t.Fatal(err)
			}
			var raw []byte
			rows.Next()
			_ = rows.Scan(&raw)
			_ = rows.Close()
			if len(raw) == 0 || containsBytes(raw, []byte("PRIVATE KEY")) {
				t.Fatalf("the store holds the value in the clear: %q", raw)
			}
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO cert_blob(key, value, modified_at) SELECT 'certs/b/b.key', value, 0 FROM cert_blob WHERE key = 'certs/a/a.key'"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Blobs(v).Get(ctx, "certs/b/b.key"); !errors.Is(err, keyslot.ErrOpen) {
				t.Fatalf("a blob copied to another key opened: %v", err)
			}
			if _, err := s.Blobs(&keyslot.Vault{}).Get(ctx, "certs/a/a.key"); !errors.Is(err, keyslot.ErrLocked) {
				t.Fatalf("a locked vault read a blob: %v", err)
			}
		})
	}
}

func containsBytes(b, sub []byte) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}

func TestInitMakesRootOnceAndItsSlotsOpen(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			if _, err := s.ServiceSlot(ctx); !errors.Is(err, ErrNotInitialized) {
				t.Fatalf("ServiceSlot before init = %v", err)
			}
			mk, _ := keyslot.NewMasterKey()
			cheap := keyslot.Params{Time: 1, MemKiB: 1024, Threads: 1}
			ps, err := keyslot.SealPassphrase(mk, "a long master passphrase", cheap)
			if err != nil {
				t.Fatal(err)
			}
			kf := make([]byte, keyslot.KeySize)
			kf[0] = 7
			ss, err := keyslot.SealService(mk, kf)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.InitRoot(ctx, "root", ps, ss); err != nil {
				t.Fatal(err)
			}
			if err := s.InitRoot(ctx, "root2", ps, ss); !errors.Is(err, ErrInitialized) {
				t.Fatalf("a second init = %v; want ErrInitialized", err)
			}
			gotPS, err := s.PassphraseSlot(ctx, "root")
			if err != nil {
				t.Fatal(err)
			}
			if got, err := keyslot.OpenPassphrase(gotPS, "a long master passphrase"); err != nil || !slices.Equal(got, mk) {
				t.Fatalf("root's slot doesn't open: %v", err)
			}
			if _, err := s.PassphraseSlot(ctx, "nobody"); !errors.Is(err, ErrNoUser) {
				t.Fatalf("an unknown user's slot = %v", err)
			}
			gotSS, err := s.ServiceSlot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := keyslot.OpenService(gotSS, kf); err != nil || !slices.Equal(got, mk) {
				t.Fatalf("the service slot doesn't open: %v", err)
			}
			v := &keyslot.Vault{}
			_ = v.Unlock(mk)
			if err := s.PutSecret(ctx, v, "cloudflare_api_token", []byte("tok")); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Secret(ctx, v, "cloudflare_api_token"); err != nil || string(got) != "tok" {
				t.Fatalf("Secret = %q, %v", got, err)
			}
			if err := s.DeleteSecret(ctx, "cloudflare_api_token"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Secret(ctx, v, "cloudflare_api_token"); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("a deleted secret = %v", err)
			}
		})
	}
}

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
			for _, table := range []string{"route", "audit", "cert_blob", "store_lease", "secret", "keyslot", "app_user", "setting", "service"} {
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
			b := s.Blobs(unlocked(t))
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
			if st, err := b.Stat(ctx, "certs/ca/a.example/a.key"); err != nil || !st.IsTerminal || st.Size != 3 { // the plaintext size
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

// TestSettingsAreKeptWithTheirAuditEntry: a setting never made reads as
// absent, one made reads back, and a second write replaces it. Each write has
// its audit entry.
func TestSettingsAreKeptWithTheirAuditEntry(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := audit.WithActor(context.Background(), "root")
			if v, ok, err := s.Setting(ctx, "acme.ca"); err != nil || ok || v != "" {
				t.Fatalf("a setting never made = %q, %v, %v; want absent", v, ok, err)
			}
			before := count(t, s, "audit")
			for _, want := range []string{"production", "staging"} {
				if err := s.PutSetting(ctx, "acme.ca", want); err != nil {
					t.Fatal(err)
				}
				if v, ok, err := s.Setting(ctx, "acme.ca"); err != nil || !ok || v != want {
					t.Fatalf("Setting = %q, %v, %v; want %q", v, ok, err, want)
				}
			}
			if n := count(t, s, "setting"); n != 1 {
				t.Fatalf("setting has %d rows after two writes of one key; want 1", n)
			}
			if n := count(t, s, "audit") - before; n != 2 {
				t.Fatalf("two writes made %d audit entries; want 2", n)
			}
		})
	}
}

// TestAuditLogReadsNewestFirst: the log comes back newest first, bounded by
// the limit, and narrowed to one action when asked.
func TestAuditLogReadsNewestFirst(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			for _, e := range [][2]string{{"auth.login", "ok"}, {"route.add", ""}, {"auth.login", "failed"}} {
				if err := s.Audit(ctx, "root", e[0], "subject", e[1]); err != nil {
					t.Fatal(err)
				}
			}
			all, err := s.AuditLog(ctx, "", 2)
			if err != nil || len(all) != 2 || all[0].Detail != "failed" || all[1].Action != "route.add" {
				t.Fatalf("the newest two = %+v, %v", all, err)
			}
			if all[0].ID <= all[1].ID || all[0].At == 0 || all[0].Actor != "root" {
				t.Fatalf("an entry lost a field or the order: %+v", all)
			}
			logins, err := s.AuditLog(ctx, "auth.login", 10)
			if err != nil || len(logins) != 2 || logins[0].Detail != "failed" || logins[1].Detail != "ok" {
				t.Fatalf("the logins = %+v, %v", logins, err)
			}
		})
	}
}

func TestStacksAreKeptAsTheyWereApplied(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			sv := s.Services()
			if err := sv.Add(ctx, "chat"); err != nil {
				t.Fatal(err)
			}
			if err := sv.Add(ctx, "chat"); !errors.Is(err, services.ErrDuplicate) {
				t.Fatalf("a second stack of the name = %v; want ErrDuplicate", err)
			}
			if err := sv.Add(ctx, "blog"); err != nil {
				t.Fatal(err)
			}
			got, err := sv.Get(ctx, "chat")
			if err != nil || got.State != services.Deploying || got.Legacy || got.Pending != nil || len(got.Applied.Units) != 0 || !got.AppliedAt.IsZero() {
				t.Fatalf("a new stack = %+v, %v", got, err)
			}

			applied := services.Applied{
				Manifest: services.NewManifest([]services.Input{{Path: "compose.yaml", Mode: 0o400, Size: 12, SHA256: "aa"}}),
				Units: []services.UnitFile{{Path: ".config/containers/systemd/chat-web.container", Kind: services.KindContainer, Service: "web",
					Body: "[Container]\nExec=\"a b\" 100%%\n", Image: "example.com/web:1", Digest: "sha256:aa",
					Ports: []services.PortUse{{Proto: "tcp", From: 8080, To: 8080}}, Inputs: []string{"web.conf"}, Needs: []string{"db"}}},
				Data: []string{"data"},
			}
			pending := services.Pending{Step: "pull", Managed: []string{"compose.yaml", "web.conf"}, Applied: applied}
			if err := sv.SetPending(ctx, "chat", pending); err != nil {
				t.Fatal(err)
			}
			got, err = sv.Get(ctx, "chat")
			if err != nil || got.Pending == nil || !reflect.DeepEqual(*got.Pending, pending) || got.State != services.Deploying {
				t.Fatalf("a stack with an apply in flight = %+v, %v", got, err)
			}
			if err := sv.SetApplied(ctx, "chat", applied); err != nil {
				t.Fatal(err)
			}
			if err := sv.SetStopped(ctx, "chat", []string{"web"}); err != nil {
				t.Fatal(err)
			}
			got, err = sv.Get(ctx, "chat")
			if err != nil || got.State != services.Deployed || got.Pending != nil || !reflect.DeepEqual(got.Applied, applied) ||
				!reflect.DeepEqual(got.Stopped, []string{"web"}) || got.AppliedAt.IsZero() {
				t.Fatalf("an applied stack = %+v, %v; want what was applied, nothing pending, and when", got, err)
			}
			if err := sv.SetStopped(ctx, "chat", nil); err != nil {
				t.Fatal(err)
			}
			if got, _ = sv.Get(ctx, "chat"); len(got.Stopped) != 0 {
				t.Fatalf("stopped = %v; want none", got.Stopped)
			}
			if err := sv.SetState(ctx, "chat", services.Removing); err != nil {
				t.Fatal(err)
			}
			all, err := sv.All(ctx)
			if err != nil || len(all) != 2 || all[0].Name != "blog" || all[1].Name != "chat" || all[1].State != services.Removing {
				t.Fatalf("All = %+v, %v; want both, by name", all, err)
			}
			if err := sv.Remove(ctx, "chat"); err != nil {
				t.Fatal(err)
			}
			for what, err := range map[string]error{
				"Get":        func() error { _, err := sv.Get(ctx, "chat"); return err }(),
				"SetState":   sv.SetState(ctx, "chat", services.Removing),
				"SetPending": sv.SetPending(ctx, "chat", pending),
				"SetApplied": sv.SetApplied(ctx, "chat", applied),
				"SetStopped": sv.SetStopped(ctx, "chat", nil),
				"Remove":     sv.Remove(ctx, "chat"),
			} {
				if !errors.Is(err, services.ErrNotFound) {
					t.Errorf("%s of a removed stack = %v; want ErrNotFound", what, err)
				}
			}

			// A row an older AutoPanel wrote from a template is read as one.
			if _, err := s.conn.ExecContext(ctx, s.q("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 1)"),
				"turn", "turn", `{"realm":"turn.example.com"}`, "deployed"); err != nil {
				t.Fatal(err)
			}
			if got, err := sv.Get(ctx, "turn"); err != nil || !got.Legacy || got.State != services.Deployed {
				t.Fatalf("a templated row = %+v, %v; want it marked", got, err)
			}
			if err := sv.Remove(ctx, "turn"); err != nil {
				t.Fatal(err)
			}
			if err := sv.Remove(ctx, "blog"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAPrivilegedActionsEntryCarriesItsOutcome(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			id, err := s.AuditAttempt(ctx, "root (local:0)", "services.deploy", `name "turn"`)
			if err != nil || id == 0 {
				t.Fatalf("AuditAttempt = %d, %v", id, err)
			}
			log, err := s.AuditLog(ctx, "", 1)
			if err != nil || len(log) != 1 || log[0].ID != id || log[0].Outcome != "attempt" || log[0].Action != "services.deploy" {
				t.Fatalf("the entry before the action = %+v, %v", log, err)
			}
			if err := s.AuditResult(ctx, id, "services.old_podman"); err != nil {
				t.Fatal(err)
			}
			if err := s.Audit(ctx, "root", "auth.login", "user root", "ok"); err != nil {
				t.Fatal(err)
			}
			log, err = s.AuditLog(ctx, "", 2)
			if err != nil || len(log) != 2 || log[1].Outcome != "services.old_podman" || log[0].Outcome != "" {
				t.Fatalf("the entries after = %+v, %v", log, err)
			}
		})
	}
}
