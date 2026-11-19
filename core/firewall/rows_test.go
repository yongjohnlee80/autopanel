package firewall

import "testing"

// TestOwners: mail, a named stack and a named forward own rules; a kind with
// no name, an unknown kind and a name with no kind do not.
func TestOwners(t *testing.T) {
	if got := StackOwner("chat"); got != "stack:chat" {
		t.Errorf("StackOwner = %q", got)
	}
	if got := ForwardOwner("ssh-box"); got != "forward:ssh-box" {
		t.Errorf("ForwardOwner = %q", got)
	}
	for owner, want := range map[string]bool{
		OwnerMail:               true,
		StackOwner("chat"):      true,
		ForwardOwner("ssh-box"): true,
		"stack:":                false,
		"forward:":              false,
		"route:x":               false,
		"chat":                  false,
		"":                      false,
		"Mail":                  false,
	} {
		if got := ValidOwner(owner); got != want {
			t.Errorf("ValidOwner(%q) = %v, want %v", owner, got, want)
		}
	}
}
