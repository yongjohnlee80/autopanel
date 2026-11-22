package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// login asks for the user and the master passphrase on the controlling
// terminal and logs the connection in. The passphrase is never echoed, and
// never read from argv or the environment.
func login(ctx context.Context, c *hostcontrol.Client) (auth.LoggedIn, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return auth.LoggedIn{}, errors.New("logging in needs a terminal")
	}
	defer tty.Close()
	fmt.Fprint(tty, "AutoPanel user [root]: ")
	user, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return auth.LoggedIn{}, err
	}
	user = strings.TrimSpace(user)
	if user == "" {
		user = "root"
	}
	fmt.Fprint(tty, "Passphrase: ")
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return auth.LoggedIn{}, err
	}
	defer clear(pass)
	// The code is always asked, and always sent (H1): empty without two-factor.
	fmt.Fprint(tty, "Two-factor code (Enter if none): ")
	code, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return auth.LoggedIn{}, err
	}
	var in auth.LoggedIn
	err = c.Call(ctx, "auth.login", auth.Login{User: user, Passphrase: string(pass), Code: strings.TrimSpace(string(code))}, &in)
	if err == nil && in.MustChange {
		fmt.Fprintln(tty, "This passphrase must be changed first: auth.passphrase.change, or the panel's My account.")
	}
	return in, err
}

// tokenLogin logs the connection in with the API token a file holds. The file
// must be the caller's own and readable by it alone (0600): a token is never
// read from the command line or the environment, which other users and logs
// can see.
func tokenLogin(ctx context.Context, c *hostcontrol.Client, path string) (auth.LoggedIn, error) {
	f, err := os.Open(path)
	if err != nil {
		return auth.LoggedIn{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return auth.LoggedIn{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return auth.LoggedIn{}, fmt.Errorf("%s can be read by others (mode %o): make it 0600", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return auth.LoggedIn{}, fmt.Errorf("%s is not yours", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return auth.LoggedIn{}, err
	}
	defer clear(b)
	var in auth.LoggedIn
	err = c.Call(ctx, "auth.token.login", auth.TokenLogin{Token: strings.TrimSpace(string(b))}, &in)
	return in, err
}

// asksAgain are the verbs that make or change a credential and so take the
// caller's passphrase again (docs/decisions/auth.md#browser-sessions).
var asksAgain = map[string]bool{"auth.token.create": true, "auth.totp.begin": true, "auth.totp.disable": true}

// passphraseAgain asks for the passphrase on the terminal and puts it into
// param, which must be a JSON object or nothing: a passphrase is never read
// from the command line, where process listings and shell history keep it.
func passphraseAgain(verb string, param any) (any, error) {
	obj, ok := param.(map[string]any)
	switch {
	case param == nil:
		obj = map[string]any{}
	case !ok:
		return nil, fmt.Errorf("%s takes a JSON object", verb)
	}
	if _, given := obj["passphrase"]; given {
		return nil, errors.New("a passphrase is never given on the command line: leave it out, and it is asked for")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New(verb + " asks for your passphrase again, which needs a terminal")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Your passphrase again, for %s: ", verb)
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	obj["passphrase"] = string(pass)
	clear(pass)
	return obj, nil
}
