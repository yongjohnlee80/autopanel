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

// AuthBusy is the answer to a question over the limit.
const AuthBusy = "busy"

// ErrAuthDown is the core not answering: held requests are 503 meanwhile.
var ErrAuthDown = errors.New("site: the core does not answer")

// ServeAuth answers the serving process on l with decide until l closes. A
// peer that is not allowed is the listener's to refuse (peercred).
func ServeAuth(l net.Listener, decide func(context.Context, coresite.ReadAsk) coresite.ReadAnswer) error {
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
				_ = json.NewEncoder(c).Encode(coresite.ReadAnswer{Status: AuthBusy})
				return
			}
			line, err := bufio.NewReaderSize(io.LimitReader(c, AuthMessage+1), AuthMessage+1).ReadBytes('\n')
			var ask coresite.ReadAsk
			if err != nil || len(line) > AuthMessage || json.Unmarshal(line, &ask) != nil {
				return // no question: no answer
			}
			ctx, cancel := context.WithTimeout(context.Background(), AuthTime)
			defer cancel()
			_ = json.NewEncoder(c).Encode(decide(ctx, ask))
		}()
	}
}

// askCore asks the core at sock. Any failure is ErrAuthDown: no answer is
// never an allow.
func askCore(ctx context.Context, sock string, ask coresite.ReadAsk) (coresite.ReadAnswer, error) {
	var ans coresite.ReadAnswer
	q, err := json.Marshal(ask)
	if err != nil || len(q)+1 > AuthMessage {
		return ans, ErrAuthDown
	}
	ctx, cancel := context.WithTimeout(ctx, AuthTime)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return ans, ErrAuthDown
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(AuthTime))
	if _, err := c.Write(append(q, '\n')); err != nil {
		return ans, ErrAuthDown
	}
	line, err := bufio.NewReaderSize(io.LimitReader(c, AuthMessage+1), AuthMessage+1).ReadBytes('\n')
	if err != nil || len(line) > AuthMessage || json.Unmarshal(line, &ans) != nil || ans.Status == AuthBusy || ans.Status == "" {
		return coresite.ReadAnswer{}, ErrAuthDown
	}
	return ans, nil
}
