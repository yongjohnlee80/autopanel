package agent

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"go.yaml.in/yaml/v3"
)

// DefaultConfig is where the agent's file is, unless --config says.
const DefaultConfig = "/etc/autopanel-agent/agent.yaml"

// File is the agent's file: the server it dials, and the only list of what
// can be reached through it.
type File struct {
	Server string `yaml:"server"`
	// Key is the key file's path; "agent.key" beside this file when empty.
	Key        string            `yaml:"key,omitempty"`
	MaxStreams int               `yaml:"max_streams,omitempty"`
	Targets    map[string]Target `yaml:"targets"`
}

// reach changes how the server is reached. Nil but in a test, which has no
// server at a public name.
var reach func(*Options)

func reached(o Options) Options {
	if reach != nil {
		reach(&o)
	}
	return o
}

const usage = `autopanel-agent: the far end of an AutoPanel tunnel.

  autopanel-agent [--config FILE] run
      Hold the tunnel up and serve the targets the file lists. The default.

  autopanel-agent [--config FILE] enroll SERVER [TOKEN]
      Make this machine the agent an enrolment token names. The token is
      read from standard input when it is not given, which keeps it out of
      the shell's history. Prints the key's fingerprint: compare it with
      the one AutoPanel's panel lists before routing anything here.

  autopanel-agent [--config FILE] fingerprint
      Print the key's fingerprint.

  autopanel-agent version

The file (default ` + DefaultConfig + `):

  server: panel.example.com
  targets:
    photos: {to: "127.0.0.1:2283"}
    nas-ssh: {to: "10.0.0.5:22"}

Only what the file lists can be reached through the tunnel. Nothing the
server sends can add a target or change where one leads.
`

// Main is the command. It returns the exit status.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	fl := flag.NewFlagSet("autopanel-agent", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() { fmt.Fprint(stderr, usage) }
	config := fl.String("config", DefaultConfig, "the agent's file")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fl.Args()
	cmd := "run"
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = runCmd(*config, stderr)
	case "enroll", "enrol":
		err = enrolCmd(*config, rest, stdin, stdout)
	case "fingerprint":
		err = fingerprintCmd(*config, stdout)
	case "version":
		fmt.Fprintln(stdout, version)
	case "help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "autopanel-agent: no such command: %s\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "autopanel-agent:", strings.TrimPrefix(err.Error(), "agent: "))
		return 1
	}
	return 0
}

// readFile reads the agent's file. A field it does not know is an error: a
// misspelt "targets" must not come out as an agent that reaches nothing.
func readFile(path string) (File, error) {
	var f File
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return f, fmt.Errorf("agent: %s: %w", path, err)
	}
	return f, nil
}

func keyPath(config string, f File) string {
	switch {
	case f.Key == "":
		return filepath.Join(filepath.Dir(config), "agent.key")
	case filepath.IsAbs(f.Key):
		return f.Key
	}
	return filepath.Join(filepath.Dir(config), f.Key)
}

// readKey reads the key file, and refuses one that others can read: the key
// is the agent.
func readKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("agent: %s can be read by others (mode %04o); it must be its owner's alone: chmod 600", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeKey(b)
}

func options(config string) (Options, error) {
	f, err := readFile(config)
	if err != nil {
		return Options{}, err
	}
	if f.Server == "" {
		return Options{}, fmt.Errorf("agent: %s names no server", config)
	}
	key, err := readKey(keyPath(config, f))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Options{}, fmt.Errorf("agent: no key yet: enrol first (autopanel-agent enroll %s)", f.Server)
		}
		return Options{}, err
	}
	o := reached(Options{Server: f.Server, Key: key, Targets: f.Targets, MaxStreams: f.MaxStreams})
	return o, o.Check()
}

func runCmd(config string, stderr io.Writer) error {
	o, err := options(config)
	if err != nil {
		return err
	}
	o.Log = slog.New(slog.NewTextHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, o)
}

func fingerprintCmd(config string, stdout io.Writer) error {
	f, err := readFile(config)
	if err != nil {
		return err
	}
	key, err := readKey(keyPath(config, f))
	if err != nil {
		return err
	}
	fp, err := Fingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, fp)
	return nil
}

// enrolCmd enrols this machine. The key is made here on the first enrolment
// and never leaves; the file is started when there is none, with the server
// and no targets. A key already here is kept and enrolled again: it is still
// this machine's.
func enrolCmd(config string, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("agent: enroll takes the server's name, and the token (or the token on standard input)")
	}
	server := args[0]
	var token string
	if len(args) == 2 {
		token = args[1]
	} else {
		line, err := bufio.NewReader(io.LimitReader(stdin, 512)).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("agent: no token was given")
		}
		token = line
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("agent: no token was given")
	}

	f, err := readFile(config)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f = File{Server: server}
	case err != nil:
		return err
	case f.Server != "" && f.Server != server:
		return fmt.Errorf("agent: %s is for the server %s, not %s", config, f.Server, server)
	}
	f.Server = server
	kp := keyPath(config, f)
	key, err := readKey(kp)
	fresh := errors.Is(err, fs.ErrNotExist)
	switch {
	case fresh:
		if key, err = NewKey(); err != nil {
			return err
		}
	case err != nil:
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	name, err := Enrol(ctx, reached(Options{Server: server, Key: key}), token)
	if err != nil {
		if errors.Is(err, ErrRefused) {
			return errors.New("agent: the server refused the token: it is wrong, used already, or more than ten minutes old")
		}
		return err
	}
	// Enrolled: now the key and the file are kept. Had writing come first, a
	// refused token would leave a key that is nobody's.
	if fresh {
		if err := os.MkdirAll(filepath.Dir(kp), 0o700); err != nil {
			return err
		}
		if err := WriteKey(kp, key); err != nil {
			return fmt.Errorf("agent: enrolled as %s, but the key could not be kept (%w): remove the agent in the panel and enrol again", name, err)
		}
	}
	if _, err := os.Stat(config); errors.Is(err, fs.ErrNotExist) {
		body := "# AutoPanel tunnel agent. Only what is listed under targets can be reached\n# through the tunnel; nothing the server sends can add to it.\nserver: " + server + "\ntargets: {}\n#  photos: {to: \"127.0.0.1:2283\"}\n"
		if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
			return err
		}
	}
	fp, err := Fingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Enrolled as %s.\nKey fingerprint: %s\nCompare it with the fingerprint AutoPanel's panel lists for %s before routing anything here.\nThen list this machine's targets in %s and start the agent.\n", name, fp, name, config)
	return nil
}
