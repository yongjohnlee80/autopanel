package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

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
	fmt.Fprint(tty, "Master passphrase: ")
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return auth.LoggedIn{}, err
	}
	var in auth.LoggedIn
	err = c.Call(ctx, "auth.login", auth.Login{User: user, Passphrase: string(pass)}, &in)
	clear(pass)
	return in, err
}
