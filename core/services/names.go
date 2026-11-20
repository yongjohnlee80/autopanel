// Package services runs stacks: a compose file the administrator writes
// becomes Podman units of one unprivileged user. The core reads the file
// itself, refuses what would reach outside the stack, shows what it accepted,
// and only then makes the user, copies the definition, pulls the images and
// starts the units. No compose program and no Docker is involved.
//
// Decision: docs/decisions/services.md
package services

import (
	"errors"
	"io/fs"
	"regexp"
)

// PortUse is a port, or a range of ports, a stack listens on.
type PortUse struct {
	Proto string `json:"proto"` // "tcp" or "udp"
	From  int    `json:"from"`
	To    int    `json:"to"` // the same as From for one port
}

// overlaps reports whether a and b claim a port in common.
func (a PortUse) overlaps(b PortUse) bool {
	return a.Proto == b.Proto && a.From <= b.To && b.From <= a.To
}

// File is a file the core writes into a stack's home.
type File struct {
	Path string      // relative to the stack user's home
	Mode fs.FileMode // 0400 for what holds a secret
	Body []byte
}

// nameRE is a stack's name, and a service's: a stack's is also part of its
// user's name ("ap-" and the name, 32 characters at most) and of its units'
// file names.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,28}$`)

// ErrBadName is a name that is not a lower-case letter followed by letters,
// digits and hyphens, 29 characters at most.
var ErrBadName = errors.New("services: a bad stack name")

// ValidName reports whether name can be a stack's, or a service's in one.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// UserOf is the host user a stack runs as.
func UserOf(name string) string { return "ap-" + name }

// builtIn are names AutoPanel's own users hold, which no stack may take: a
// stack is run as "ap-" and its name, and would get that user. "site" is the
// site's builder (ap-site).
var builtIn = map[string]bool{"site": true}

// BuiltIn reports whether name is one of AutoPanel's own users' names.
func BuiltIn(name string) bool { return builtIn[name] }

// owned reports whether name is a stack nobody but AutoPanel may write: one
// of its own users' names, or a stack a module owns (mail).
func (m *Module) owned(name string) bool {
	return builtIn[name] || (m.guard != nil && m.guard.Owns(name))
}
