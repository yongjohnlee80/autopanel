package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTheTokenIsCheckedWithCloudflare: certs.cloudflare.set keeps a token only
// once Cloudflare says it is active. A refusal and a silence are told apart, so
// the panel says whether to fix the token or to try again.
func TestTheTokenIsCheckedWithCloudflare(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/user/tokens/verify" {
			http.NotFound(w, r)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer good":
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"status":"active"}}`))
		case "Bearer paused":
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"status":"disabled"}}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"result":null}`))
		}
	}))
	verify := verifyAt(api.URL)
	ctx := context.Background()
	if err := verify(ctx, "good"); err != nil {
		t.Fatalf("an active token: %v", err)
	}
	for _, tok := range []string{"mistyped", "paused"} {
		if err := verify(ctx, tok); !errors.Is(err, errTokenRefused) {
			t.Fatalf("token %q: %v; want errTokenRefused", tok, err)
		}
	}
	api.Close()
	if err := verify(ctx, "good"); !errors.Is(err, errNoCloudflare) {
		t.Fatalf("with no API answering: %v; want errNoCloudflare", err)
	}
}
