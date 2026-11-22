package hostcmd

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlyANamedToolRuns(t *testing.T) {
	if _, err := Run(context.Background(), Tool{}); !errors.Is(err, ErrNoTool) {
		t.Errorf("a tool with no path = %v; want ErrNoTool", err)
	}
	if _, err := Run(context.Background(), Tool{"/nonexistent/autopanel-test-tool"}); !errors.Is(err, ErrNoTool) {
		t.Errorf("a tool the host lacks = %v; want ErrNoTool", err)
	}
}

func TestOutputIsBounded(t *testing.T) {
	var b bounded
	chunk := make([]byte, 1<<20)
	for i := 0; i < 6; i++ {
		if n, err := b.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if b.Len() != maxOutput {
		t.Errorf("kept %d bytes; want %d", b.Len(), maxOutput)
	}
}

// TestThisIsTheOnlyPackageThatRunsCommands reads every Go file of the module
// but the tests: os/exec may be imported here and nowhere else, so every
// command the core runs is one of this package's tools, with arguments and no
// shell.
func TestThisIsTheOnlyPackageThatRunsCommands(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "bin" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"os/exec"` && filepath.Base(filepath.Dir(path)) != "hostcmd" {
				t.Errorf("%s imports os/exec; only internal/hostcmd may", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestStreamWritesAsItRuns runs a tool whose output goes to the writers
// given, in the directory and with the environment given beside the fixed
// PATH and locale; a tool that is not named, or not there, is ErrNoTool, and
// a failing one is its own error.
func TestStreamWritesAsItRuns(t *testing.T) {
	ctx := context.Background()
	if err := Stream(ctx, Tool{}, "", nil, io.Discard, io.Discard); !errors.Is(err, ErrNoTool) {
		t.Errorf("no tool: %v", err)
	}
	if err := Stream(ctx, Tool{"/nonexistent/autopanel-test-tool"}, "", nil, io.Discard, io.Discard); !errors.Is(err, ErrNoTool) {
		t.Errorf("a tool that is not there: %v", err)
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if err := Stream(ctx, Tool{"/usr/bin/env"}, dir, []string{"AUTOPANEL_TEST=here"}, &out, &errOut); err != nil {
		t.Fatalf("Stream: %v (%s)", err, errOut.String())
	}
	for _, want := range []string{"AUTOPANEL_TEST=here\n", "LANG=C\n", "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the environment lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := Stream(ctx, Tool{"/usr/bin/env"}, dir, nil, &out, &errOut, "pwd"); err != nil || strings.TrimSpace(out.String()) != dir {
		t.Errorf("the directory = %q, %v; want %s", out.String(), err, dir)
	}
	if err := Stream(ctx, Tool{"/usr/bin/env"}, dir, nil, io.Discard, &errOut, "false"); err == nil || errors.Is(err, ErrNoTool) {
		t.Errorf("a failing tool: %v", err)
	}
}
