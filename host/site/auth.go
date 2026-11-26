package site

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

// THE AUTH SOCKET — how the serving process asks the core whether a reader
// may have a held file. One question and one answer a connection, each one
// line of JSON of at most AuthMessage bytes, within AuthTime. The core
// answers at most AuthInFlight at once; one more is told it is busy, and the
// reader gets 503. The socket speaks nothing else, and is not the control
// socket: it reaches no verb.

const (
	AuthMessage  = 8 << 10
	AuthTime     = 2 * time.Second
	AuthInFlight = 16
)

// ErrAuthDown is the core not answering: held requests are 503 meanwhile.
var ErrAuthDown = errors.New("site: the core does not answer")

// Core is what the socket asks: whether a reader may have a held file, and
// whether a passphrase unlocks a protected node. Nothing else.
type Core interface {
	MayReadPath(context.Context, coresite.ReadAsk) coresite.ReadAnswer
	Unlock(context.Context, coresite.UnlockAsk) coresite.UnlockAnswer
}

// authQuestion is one line on the socket: a read, or an unlock.
type authQuestion struct {
	Read   *coresite.ReadAsk   `json:"read,omitempty"`
	Unlock *coresite.UnlockAsk `json:"unlock,omitempty"`
}

// authAnswer is the line that answers it.
type authAnswer struct {
	Busy   bool                   `json:"busy,omitempty"`
	Read   *coresite.ReadAnswer   `json:"read,omitempty"`
	Unlock *coresite.UnlockAnswer `json:"unlock,omitempty"`
}

// ServeAuth answers the serving process on l from core until l closes. A
// peer that is not allowed is the listener's to refuse (peercred).
func ServeAuth(l net.Listener, core Core) error {
	slots := make(chan struct{}, AuthInFlight)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(AuthTime))
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				_ = json.NewEncoder(c).Encode(authAnswer{Busy: true})
				return
			}
			line, err := bufio.NewReaderSize(io.LimitReader(c, AuthMessage+1), AuthMessage+1).ReadBytes('\n')
			var q authQuestion
			if err != nil || len(line) > AuthMessage || json.Unmarshal(line, &q) != nil || (q.Read == nil) == (q.Unlock == nil) {
				return // no question, or two: no answer
			}
			ctx, cancel := context.WithTimeout(context.Background(), AuthTime)
			defer cancel()
			var a authAnswer
			if q.Read != nil {
				ans := core.MayReadPath(ctx, *q.Read)
				a.Read = &ans
			} else {
				ans := core.Unlock(ctx, *q.Unlock)
				a.Unlock = &ans
			}
			_ = json.NewEncoder(c).Encode(a)
		}()
	}
}

// ask sends one question to the core at sock and reads its answer. Any
// failure is ErrAuthDown: no answer is never an allow.
func ask(ctx context.Context, sock string, q authQuestion) (authAnswer, error) {
	var a authAnswer
	line, err := json.Marshal(q)
	if err != nil || len(line)+1 > AuthMessage {
		return a, ErrAuthDown
	}
	ctx, cancel := context.WithTimeout(ctx, AuthTime)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return a, ErrAuthDown
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(AuthTime))
	if _, err := c.Write(append(line, '\n')); err != nil {
		return a, ErrAuthDown
	}
	// An answer may hold the unlock form: larger than a question, still bounded.
	got, err := bufio.NewReaderSize(io.LimitReader(c, 4*AuthMessage+1), 4*AuthMessage+1).ReadBytes('\n')
	if err != nil || len(got) > 4*AuthMessage || json.Unmarshal(got, &a) != nil || a.Busy {
		return authAnswer{}, ErrAuthDown
	}
	return a, nil
}

// askCore asks the core whether a reader may have what a request names.
func askCore(ctx context.Context, sock string, q coresite.ReadAsk) (coresite.ReadAnswer, error) {
	a, err := ask(ctx, sock, authQuestion{Read: &q})
	if err != nil || a.Read == nil || a.Read.Status == "" {
		return coresite.ReadAnswer{}, ErrAuthDown
	}
	return *a.Read, nil
}

// askUnlock asks the core whether a passphrase unlocks a protected node.
func askUnlock(ctx context.Context, sock string, q coresite.UnlockAsk) (coresite.UnlockAnswer, error) {
	a, err := ask(ctx, sock, authQuestion{Unlock: &q})
	if err != nil || a.Unlock == nil || a.Unlock.Status == "" {
		return coresite.UnlockAnswer{}, ErrAuthDown
	}
	return *a.Unlock, nil
}
