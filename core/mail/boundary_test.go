package mail

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Mail's rules name no mail server (docs/decisions/mail.md#mails-rules-name-no-mail-server):
// core/mail and core/mail/provider reach a server only through the provider
// interfaces. These tests fail when one reaches past them.

// serverWords are names only an SDK may use.
var serverWords = []string{"stalwart", "jmap"}

// TestTheRulesImportNoSDK: neither package depends, even indirectly, on an
// SDK (sdk/...).
func TestTheRulesImportNoSDK(t *testing.T) {
	for _, pkg := range []string{".", "./provider"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		for _, dep := range strings.Fields(string(out)) {
			if strings.Contains(dep, "/autopanel/sdk/") {
				t.Errorf("%s depends on %s", pkg, dep)
			}
		}
	}
}

// TestTheRulesNameNoServer: no identifier or string of either package's
// sources (tests aside) names a server. Comments may, to cite a decision.
func TestTheRulesNameNoServer(t *testing.T) {
	for _, dir := range []string{".", "provider"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, nil, 0) // no comments
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				var text string
				switch v := n.(type) {
				case *ast.Ident:
					text = v.Name
				case *ast.BasicLit:
					text = v.Value
				default:
					return true
				}
				low := strings.ToLower(text)
				for _, w := range serverWords {
					if strings.Contains(low, w) {
						t.Errorf("%s: %q names a mail server", fset.Position(n.Pos()), text)
					}
				}
				return true
			})
		}
	}
}
