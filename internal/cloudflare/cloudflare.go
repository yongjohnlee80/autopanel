// Package cloudflare is the few calls of Cloudflare's API that mail's DNS
// needs: verify a token, find the zone that holds a name, and list, create,
// update and delete its records by id. Standard library only. The token is
// read from the vault for each call and never logged.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// API is Cloudflare's API v4.
const API = "https://api.cloudflare.com/client/v4"

// Client calls the API with a token.
type Client struct {
	Base  string // API, or a test server's
	Token func(ctx context.Context) (string, error)
	HTTP  *http.Client
}

// New is a client of the real API.
func New(token func(ctx context.Context) (string, error)) *Client {
	return &Client{Base: API, Token: token, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// Error is the API's refusal.
type Error struct {
	Status   int
	Messages []string
}

func (e *Error) Error() string {
	return fmt.Sprintf("cloudflare: %d: %s", e.Status, strings.Join(e.Messages, "; "))
}

// ErrNoZone is a name no zone the token reaches holds.
var ErrNoZone = errors.New("cloudflare: no zone the token can reach holds that name")

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (envelope, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return envelope{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return envelope{}, err
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return envelope{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return envelope{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return envelope{}, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, &Error{Status: resp.StatusCode, Messages: []string{"an answer that is not JSON"}}
	}
	if !env.Success || resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Messages = append(e.Messages, strconv.Itoa(m.Code)+" "+m.Message)
		}
		return env, e
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return env, err
		}
	}
	return env, nil
}

// Verify checks that the token is valid and active.
func (c *Client) Verify(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return &Error{Status: 200, Messages: []string{"the token is " + r.Status}}
	}
	return nil
}

// Zone is one of the account's zones.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ZoneFor finds the zone that holds name: the name itself, or the nearest
// parent the token can reach (a registry subdomain lives in its parent's zone).
func (c *Client) ZoneFor(ctx context.Context, name string) (Zone, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []Zone
		if _, err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil, &zones); err != nil {
			return Zone{}, err
		}
		for _, z := range zones {
			if z.Name == candidate {
				return z, nil
			}
		}
	}
	return Zone{}, ErrNoZone
}

// Record is a DNS record as Cloudflare holds it.
type Record struct {
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Content  string         `json:"content,omitempty"`
	TTL      int            `json:"ttl"` // 1 is automatic
	Priority *uint16        `json:"priority,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	Proxied  *bool          `json:"proxied,omitempty"`
}

// Records lists a zone's records, every page.
func (c *Client) Records(ctx context.Context, zoneID string) ([]Record, error) {
	var out []Record
	for page := 1; page <= 50; page++ {
		var rs []Record
		env, err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records?per_page=100&page="+strconv.Itoa(page), nil, &rs)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
		if env.ResultInfo.TotalPages <= page {
			break
		}
	}
	return out, nil
}

// Create makes a record and answers it with its id.
func (c *Client) Create(ctx context.Context, zoneID string, r Record) (Record, error) {
	var made Record
	_, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", r, &made)
	return made, err
}

// Update replaces a record by its id.
func (c *Client) Update(ctx context.Context, zoneID, id string, r Record) error {
	_, err := c.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), r, nil)
	return err
}

// Delete removes a record by its id.
func (c *Client) Delete(ctx context.Context, zoneID, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, nil)
	return err
}
