package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fake(t *testing.T, h http.HandlerFunc) *Client {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, Token: func(context.Context) (string, error) { return "tok", nil }, HTTP: srv.Client()}
}

func ok(w http.ResponseWriter, result any, pages int) {
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result,
		"result_info": map[string]any{"page": 1, "total_pages": pages}})
}

func TestZoneForWalksUpToTheParent(t *testing.T) {
	var asked []string
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatal("no bearer token")
		}
		name := r.URL.Query().Get("name")
		asked = append(asked, name)
		if name == "example.com" {
			ok(w, []Zone{{ID: "z1", Name: "example.com"}}, 1)
			return
		}
		ok(w, []Zone{}, 1)
	})
	z, err := c.ZoneFor(context.Background(), "lists.example.com")
	if err != nil || z.ID != "z1" || strings.Join(asked, ",") != "lists.example.com,example.com" {
		t.Fatalf("ZoneFor = %+v, %v; asked %v", z, err, asked)
	}
	if _, err := c.ZoneFor(context.Background(), "example.org"); !errors.Is(err, ErrNoZone) {
		t.Fatalf("no zone: %v", err)
	}
}

func TestRecordsPagesAndRefusals(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("page") == "1":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []Record{{ID: "a", Type: "MX", Name: "example.com"}},
				"result_info": map[string]any{"page": 1, "total_pages": 2}})
		case r.Method == http.MethodGet:
			ok(w, []Record{{ID: "b", Type: "TXT", Name: "example.com"}}, 2)
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "Authentication error"}}})
		}
	})
	rs, err := c.Records(context.Background(), "z1")
	if err != nil || len(rs) != 2 {
		t.Fatalf("two pages: %+v, %v", rs, err)
	}
	_, err = c.Create(context.Background(), "z1", Record{Type: "TXT", Name: "x", Content: "y"})
	var e *Error
	if !errors.As(err, &e) || e.Status != 403 || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("a refusal: %v", err)
	}
}
