package stalwart

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// THE OUTGOING QUEUE — what waits to leave the server, summed for the
// panel's Mail widget: how many, how many of them last failed, the oldest,
// and the failing ones. Read with two calls, of at most limit messages.

// queuedMessage is one message of Stalwart's queue, as x:QueuedMessage/get
// answers the properties the summary needs.
type queuedMessage struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	NextRetry  string `json:"nextRetry"`
	ReturnPath string `json:"returnPath"`
	Recipients map[string]struct {
		RetryCount int    `json:"retryCount"`
		RetryDue   string `json:"retryDue"`
		Status     struct {
			Type             string `json:"@type"`
			ErrorType        string `json:"errorType"`
			ErrorMessage     string `json:"errorMessage"`
			ResponseHostname string `json:"responseHostname"`
			ResponseMessage  string `json:"responseMessage"`
		} `json:"status"`
	} `json:"recipients"`
}

// failing reports whether a recipient's last attempt failed: the two
// failures Stalwart names. Any other status (not tried yet, done) is none.
func failing(statusType string) bool {
	return statusType == "TemporaryFailure" || statusType == "PermanentFailure"
}

func (s server) Queue(ctx context.Context, limit int) (provider.Queue, error) {
	if limit <= 0 || limit > provider.MaxQueue {
		limit = provider.MaxQueue
	}
	var q struct {
		IDs   []string `json:"ids"`
		Total *int     `json:"total"`
	}
	// One more than is counted, to know there are more.
	if err := s.c.call(ctx, "x:QueuedMessage/query", map[string]any{"limit": limit + 1, "calculateTotal": true}, &q); err != nil {
		return provider.Queue{}, refused(err)
	}
	out := provider.Queue{Sample: []provider.QueuedMessage{}}
	if len(q.IDs) > limit || (q.Total != nil && *q.Total > limit) {
		out.More = true
	}
	if len(q.IDs) > limit {
		q.IDs = q.IDs[:limit]
	}
	if len(q.IDs) == 0 {
		return out, nil
	}
	var got struct {
		List []queuedMessage `json:"list"`
	}
	if err := s.c.call(ctx, "x:QueuedMessage/get", map[string]any{"ids": q.IDs,
		"properties": []string{"id", "createdAt", "nextRetry", "returnPath", "recipients"}}, &got); err != nil {
		return provider.Queue{}, refused(err)
	}
	out.Waiting = len(got.List)
	for _, m := range got.List {
		since, _ := time.Parse(time.RFC3339, m.CreatedAt)
		if !since.IsZero() && (out.Oldest.IsZero() || since.Before(out.Oldest)) {
			out.Oldest = since
		}
		names := make([]string, 0, len(m.Recipients))
		for to, r := range m.Recipients {
			if failing(r.Status.Type) {
				names = append(names, to)
			}
		}
		if len(names) == 0 {
			continue
		}
		out.Failing++
		sort.Strings(names)
		r := m.Recipients[names[0]]
		next, _ := time.Parse(time.RFC3339, r.RetryDue)
		why := []string{r.Status.ErrorType, r.Status.ResponseHostname, r.Status.ErrorMessage, r.Status.ResponseMessage}
		why = slices.DeleteFunc(why, func(s string) bool { return s == "" })
		out.Sample = append(out.Sample, provider.QueuedMessage{From: printable(m.ReturnPath, 254), To: printable(names[0], 254), Others: len(names) - 1,
			Since: since, Attempts: r.RetryCount, Next: next, Why: printable(strings.Join(why, ": "), provider.MaxQueueWhy)})
	}
	sort.SliceStable(out.Sample, func(i, j int) bool { return out.Sample[i].Since.Before(out.Sample[j].Since) })
	if len(out.Sample) > provider.MaxQueueSample {
		out.Sample = out.Sample[:provider.MaxQueueSample]
	}
	return out, nil
}

// printable is s with every control character a space, cut at max bytes on a
// character's boundary: what another server said, safe to show in a terminal.
func printable(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		if b.Len()+len(string(r)) > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
