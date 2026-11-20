package store

import (
	"context"
	"errors"
	"testing"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// TestBrowserSessionsOnTheStore: the store's side of a session, on each
// engine: found by its hash alone, the oldest pushed out at the limit, the
// expired removed when one is made, a user's ended together or all but one,
// and gone with their user.
func TestBrowserSessionsOnTheStore(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			st := s.Sessions()
			ann, bob := testUser(t, s, "ann"), testUser(t, s, "bob")
			mk := func(user int64, n byte, at int64) auth.Session {
				v := auth.Session{UserID: user, Host: auth.HostApp, CreatedAt: at, SeenAt: at, Client: "203.0.113.1", Agent: "test"}
				v.IDHash[0], v.IDHash[1], v.CSRFKey[0] = byte(user), n, n
				return v
			}
			never := func(auth.Session) bool { return false }
			for i := byte(1); i <= 3; i++ {
				if err := st.PutSession(ctx, mk(ann, i, 100+int64(i)), 3, never); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.PutSession(ctx, mk(bob, 1, 100), 3, never); err != nil {
				t.Fatal(err)
			}
			got, err := st.Session(ctx, mk(ann, 2, 0).IDHash)
			if err != nil || got != mk(ann, 2, 102) {
				t.Fatalf("Session = %+v, %v", got, err)
			}
			if _, err := st.Session(ctx, mk(ann, 9, 0).IDHash); !errors.Is(err, auth.ErrNoSession) {
				t.Fatalf("an unknown hash: %v", err)
			}
			// A fourth pushes out the oldest of that user's, and nobody else's.
			if err := st.PutSession(ctx, mk(ann, 4, 200), 3, never); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Session(ctx, mk(ann, 1, 0).IDHash); !errors.Is(err, auth.ErrNoSession) {
				t.Fatal("the oldest session outlived the limit")
			}
			if _, err := st.Session(ctx, mk(bob, 1, 0).IDHash); err != nil {
				t.Fatalf("another user's session went with it: %v", err)
			}
			if list, err := st.UserSessions(ctx, ann); err != nil || len(list) != 3 || list[0].CreatedAt != 200 || list[2].CreatedAt != 102 {
				t.Fatalf("UserSessions = %+v, %v", list, err)
			}
			// The last call's time only moves forward.
			h := mk(ann, 4, 0).IDHash
			if err := st.TouchSession(ctx, h, 260); err != nil {
				t.Fatal(err)
			}
			if err := st.TouchSession(ctx, h, 230); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.Session(ctx, h); got.SeenAt != 260 {
				t.Fatalf("seen at %d; want 260", got.SeenAt)
			}
			// The expired go when one is made, whoever's they are.
			old := func(v auth.Session) bool { return v.CreatedAt < 150 }
			if err := st.PutSession(ctx, mk(bob, 2, 300), 3, old); err != nil {
				t.Fatal(err)
			}
			if n := count(t, s, "web_session"); n != 2 {
				t.Fatalf("%d sessions after the expired were removed; want ann's newest and bob's new one", n)
			}
			// All of a user's but one; then all.
			for i := byte(5); i <= 6; i++ {
				if err := st.PutSession(ctx, mk(ann, i, 300+int64(i)), 5, never); err != nil {
					t.Fatal(err)
				}
			}
			keep := mk(ann, 6, 0).IDHash
			if n, err := st.EndUserSessions(ctx, ann, &keep); err != nil || n != 2 {
				t.Fatalf("EndUserSessions but one = %d, %v", n, err)
			}
			if _, err := st.Session(ctx, keep); err != nil {
				t.Fatal("the kept session was ended")
			}
			if err := st.EndSession(ctx, keep); err != nil {
				t.Fatal(err)
			}
			if err := st.EndSession(ctx, keep); err != nil {
				t.Fatalf("ending a session twice: %v", err)
			}
			if n, err := st.EndUserSessions(ctx, ann, nil); err != nil || n != 0 {
				t.Fatalf("EndUserSessions with none left = %d, %v", n, err)
			}
			// A session goes with its user.
			if _, err := s.conn.ExecContext(ctx, s.q("DELETE FROM app_user WHERE id = ?"), bob); err != nil {
				t.Fatal(err)
			}
			if n := count(t, s, "web_session"); n != 0 {
				t.Fatalf("%d sessions outlived their user", n)
			}
			// The store refuses what is no session.
			bad := mk(ann, 7, 400)
			bad.Host = "api"
			if err := st.PutSession(ctx, bad, 3, never); err == nil {
				t.Fatal("a session on a host that has none was stored")
			}
		})
	}
}
