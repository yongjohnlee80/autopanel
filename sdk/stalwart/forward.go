package stalwart

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// FORWARDING — an account's mail sent on to addresses outside. Stalwart has
// no forwarding field: it is a Sieve redirect in the account's own script.
// AutoPanel writes one script, of one fixed shape, and reads back only that
// shape; a script it did not write is never changed. Decision:
// docs/decisions/mail.md, "Forwarding".

// forwardScript is the name of the script AutoPanel writes.
const forwardScript = "autopanel-forward"

const (
	forwardMarker  = "# autopanel-forward v1: written by AutoPanel. Change it from Mail > Accounts, not here.\n"
	forwardRequire = "require [\"copy\", \"spamtestplus\", \"relational\", \"comparator-i;ascii-numeric\"];\n"
	// Only what the server did not mark as spam is sent on: forwarded spam is
	// sent by us. A message marked as spam falls to the implicit keep.
	forwardIf      = "if not spamtest :value \"ge\" :comparator \"i;ascii-numeric\" :percent \"50\" {\n"
	forwardLine    = "    redirect :copy \""
	forwardLineEnd = "\";\n"
	forwardDiscard = "    discard;\n"
	forwardEnd     = "}\n"
)

// generateForward is the script that forwards to f.To. An address reaches it
// only inside a quoted string, and the caller has refused any with a quote, a
// backslash or a control character.
func generateForward(f provider.Forward) string {
	var b strings.Builder
	b.WriteString(forwardMarker + forwardRequire + forwardIf)
	for _, to := range f.To {
		b.WriteString(forwardLine + to + forwardLineEnd)
	}
	if !f.Keep {
		b.WriteString(forwardDiscard)
	}
	b.WriteString(forwardEnd)
	return b.String()
}

// parseForward reads a script back. ok only when it is, byte for byte, what
// generateForward writes for what it answers: one changed by hand is not
// AutoPanel's.
func parseForward(script string) (f provider.Forward, ok bool) {
	rest, found := strings.CutPrefix(script, forwardMarker+forwardRequire+forwardIf)
	if !found {
		return f, false
	}
	f.Keep = true
	for {
		line, after, found := strings.Cut(rest, "\n")
		if !found {
			return provider.Forward{}, false
		}
		line += "\n"
		switch {
		case strings.HasPrefix(line, forwardLine) && strings.HasSuffix(line, forwardLineEnd):
			to := line[len(forwardLine) : len(line)-len(forwardLineEnd)]
			if !plainAddress(to) {
				return provider.Forward{}, false
			}
			f.To = append(f.To, to)
		case line == forwardDiscard:
			f.Keep = false
		case line == forwardEnd:
			if len(f.To) == 0 || generateForward(f) != script {
				return provider.Forward{}, false
			}
			return f, true
		default:
			return provider.Forward{}, false
		}
		rest = after
	}
}

// plainAddress reports whether to may stand inside the script's quoted
// string: one @, and no quote, backslash, space or control character. The
// core checks an address's form; this is the script's own last word, for
// what it writes and for what it reads back.
func plainAddress(to string) bool {
	if strings.Count(to, "@") != 1 || len(to) > 254 {
		return false
	}
	for _, r := range to {
		if r <= 0x20 || r == 0x7f || r == '"' || r == '\\' || r > 0x7e {
			return false
		}
	}
	return true
}

// sieveCaps are the capabilities a Sieve method needs.
var sieveCaps = []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:sieve"}

// sieveScript is one of an account's scripts.
type sieveScript struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	BlobID   string `json:"blobId"`
	IsActive bool   `json:"isActive"`
}

// sieveScripts are the account's Sieve scripts.
func (c *Client) sieveScripts(ctx context.Context, accountID string) ([]sieveScript, error) {
	var got struct {
		List []sieveScript `json:"list"`
	}
	err := c.callUsing(ctx, sieveCaps, "SieveScript/get", map[string]any{"accountId": accountID}, &got)
	return got.List, err
}

// sieveSet is one SieveScript/set on the account.
func (c *Client) sieveSet(ctx context.Context, accountID string, args map[string]any) error {
	args["accountId"] = accountID
	var a setAnswer
	if err := c.callUsing(ctx, sieveCaps, "SieveScript/set", args, &a); err != nil {
		return err
	}
	return a.refused("SieveScript/set")
}

// blob reads one of the account's blobs, of at most max bytes.
func (c *Client) blob(ctx context.Context, accountID, blobID string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/jmap/download/"+url.PathEscape(accountID)+"/"+url.PathEscape(blobID)+"/script", nil)
	if err != nil {
		return nil, err
	}
	raw, status, err := c.do(req, max)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("mail: reading a script: Stalwart answered %d", status)
	}
	return raw, nil
}

// upload stores data as a blob of the account's and answers its ID.
func (c *Client) upload(ctx context.Context, accountID string, data []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/jmap/upload/"+url.PathEscape(accountID)+"/", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/sieve")
	raw, status, err := c.do(req, 64<<10)
	if err != nil {
		return "", err
	}
	var up struct {
		BlobID string `json:"blobId"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &up) != nil || up.BlobID == "" {
		return "", fmt.Errorf("mail: storing a script: Stalwart answered %d", status)
	}
	return up.BlobID, nil
}

// do sends req with the client's credential and reads at most max bytes of
// the answer.
func (c *Client) do(req *http.Request, max int64) ([]byte, int, error) {
	auth, err := c.auth(req.Context())
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", auth)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, resp.StatusCode, ErrUnauthorized
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(raw)) > max {
		return nil, resp.StatusCode, fmt.Errorf("mail: Stalwart's answer is larger than %d bytes", max)
	}
	return raw, resp.StatusCode, nil
}

// redirectLimit is how many redirects the server runs for one message of a
// user's script: the lesser of its redirect limit and its limit on messages a
// script sends. One, unless an administrator raised them.
func (c *Client) redirectLimit(ctx context.Context) (int, error) {
	var got struct {
		List []struct {
			MaxRedirects   *int `json:"maxRedirects"`
			MaxOutMessages *int `json:"maxOutMessages"`
		} `json:"list"`
	}
	if err := c.call(ctx, "x:SieveUserInterpreter/get", map[string]any{"ids": []string{"singleton"}, "properties": []string{"maxRedirects", "maxOutMessages"}}, &got); err != nil {
		return 0, err
	}
	n := 1 // the server's default
	if len(got.List) == 1 {
		if r := got.List[0].MaxRedirects; r != nil {
			n = *r
		}
		if out := got.List[0].MaxOutMessages; out != nil && *out < n {
			n = *out
		}
	}
	return max(min(n, provider.MaxForwards), 0), nil
}

// maxScript is the most of a script that is read back: AutoPanel's own is
// far smaller, and a larger one is not AutoPanel's.
const maxScript = 16 << 10

// forwardState reads how the account forwards: by AutoPanel's script when it
// is the active one and is what AutoPanel writes; other when another script
// is active, or the one of AutoPanel's name was changed by hand.
func (s server) forwardState(ctx context.Context, accountID string) (st provider.ForwardState, ours *sieveScript, err error) {
	scripts, err := s.c.sieveScripts(ctx, accountID)
	if err != nil {
		return st, nil, err
	}
	var active *sieveScript
	for i := range scripts {
		if scripts[i].IsActive {
			active = &scripts[i]
		}
		if scripts[i].Name == forwardScript {
			ours = &scripts[i]
		}
	}
	if st.Max, err = s.c.redirectLimit(ctx); err != nil {
		return st, nil, err
	}
	if active != nil && active != ours {
		st.Other = true
		return st, ours, nil
	}
	if ours == nil {
		return st, nil, nil
	}
	// The script's text is read only now: it is AutoPanel's by name, and
	// either active or the only candidate to replace.
	raw, err := s.c.blob(ctx, accountID, ours.BlobID, maxScript)
	if err != nil {
		return st, ours, err
	}
	f, ok := parseForward(string(raw))
	switch {
	case !ok:
		st.Other = true // of AutoPanel's name, and not what AutoPanel writes
	case ours.IsActive:
		st.Forward = f
	}
	return st, ours, nil
}

func (s server) Forward(ctx context.Context, accountID string) (provider.ForwardState, error) {
	st, _, err := s.forwardState(ctx, accountID)
	return st, refused(err)
}

func (s server) SetForward(ctx context.Context, accountID string, f provider.Forward) error {
	st, ours, err := s.forwardState(ctx, accountID)
	if err != nil {
		return refused(err)
	}
	if st.Other {
		return &provider.Refusal{Why: "a Sieve script AutoPanel did not write is the account's own: forwarding is set in that script, in the mail server"}
	}
	if len(f.To) == 0 {
		if ours == nil {
			return nil // nothing to turn off
		}
		if ours.IsActive {
			if err := s.c.sieveSet(ctx, accountID, map[string]any{"onSuccessDeactivateScript": true}); err != nil {
				return refused(err)
			}
		}
		return refused(s.c.sieveSet(ctx, accountID, map[string]any{"destroy": []string{ours.ID}}))
	}
	if len(f.To) > st.Max {
		return provider.ErrTooManyForwards
	}
	for _, to := range f.To {
		if !plainAddress(to) {
			return &provider.Refusal{Why: "an address that cannot be written into a script"}
		}
	}
	blob, err := s.c.upload(ctx, accountID, []byte(generateForward(f)))
	if err != nil {
		return refused(err)
	}
	if ours != nil {
		return refused(s.c.sieveSet(ctx, accountID, map[string]any{
			"update": map[string]any{ours.ID: map[string]any{"blobId": blob}}, "onSuccessActivateScript": ours.ID}))
	}
	return refused(s.c.sieveSet(ctx, accountID, map[string]any{
		"create": map[string]any{"s": map[string]any{"name": forwardScript, "blobId": blob}}, "onSuccessActivateScript": "#s"}))
}
