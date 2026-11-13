package services

import (
	"sort"
	"strconv"
	"strings"
)

// WHAT A CONFIRMATION COVERS. The review of a stack answers the hash of every
// file of its definition, and an apply is refused unless it is given that
// hash: an edit of .env or of a mounted configuration file between the review
// and the apply changes it, as an edit of the compose file does.

// Input is one file of a stack's definition.
type Input struct {
	Path   string `json:"path"` // relative to the stack's folder
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is every definition input of a stack, in path order: compose.yaml,
// .env, each env_file, and each file under a read-only mount's source. A
// writable mount's source is the stack's data, and is not in it.
type Manifest struct {
	Files  []Input `json:"files"`
	SHA256 string  `json:"sha256"` // over each file's path, mode and hash, in order
}

// NewManifest is the manifest of files.
func NewManifest(files []Input) Manifest {
	files = append([]Input{}, files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var b strings.Builder
	for _, f := range files {
		b.WriteString(f.Path + "\x00" + strconv.FormatUint(uint64(f.Mode), 8) + "\x00" + f.SHA256 + "\n")
	}
	return Manifest{Files: files, SHA256: hash([]byte(b.String()))}
}

// paths are the manifest's files.
func (m Manifest) paths() []string {
	out := make([]string, len(m.Files))
	for i, f := range m.Files {
		out[i] = f.Path
	}
	return out
}

// under is what the manifest holds at p, or inside it: each file's path with
// its hash and mode.
func (m Manifest) under(p string) map[string]string {
	out := map[string]string{}
	for _, f := range m.Files {
		if within(f.Path, p) {
			out[f.Path] = f.SHA256 + " " + strconv.FormatUint(uint64(f.Mode), 8)
		}
	}
	return out
}

// sameUnder reports whether m and o hold the same files at p.
func (m Manifest) sameUnder(o Manifest, p string) bool {
	a, b := m.under(p), o.under(p)
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Applied is a stack as an apply left it.
type Applied struct {
	Manifest Manifest   `json:"manifest"`
	Units    []UnitFile `json:"units"`
	Data     []string   `json:"data"`  // the sources of its writable mounts
	Roots    []string   `json:"roots"` // its env_files and the sources of its read-only mounts: files, or folders of them
}

// managed is every path of the stack's folder that an apply put there: each
// file of the manifest, and each managed file or folder the compose file names.
func (a Applied) managed() []string {
	return append(a.Manifest.paths(), a.Roots...)
}

// unit is the applied container unit of service.
func (a Applied) unit(service string) (UnitFile, bool) {
	for _, u := range a.Units {
		if u.Kind == KindContainer && u.Service == service {
			return u, true
		}
	}
	return UnitFile{}, false
}

// ports are the host ports the applied units claim.
func (a Applied) ports() []PortUse {
	var out []PortUse
	for _, u := range a.Units {
		out = append(out, u.Ports...)
	}
	return out
}

// Pending is an apply that has begun and not ended. It holds everything the
// stack had before together with everything the apply may make, so that an
// apply after any number of failures still knows each unit, port and file
// that may be on the host.
type Pending struct {
	Step string `json:"step"` // the step the apply reached
	// Prepared marks a stack whose user, files and images are in place and
	// whose units are not: prepare ends there.
	Prepared bool     `json:"prepared,omitempty"`
	Managed  []string `json:"managed"` // every managed path, before or after: files, and the folders that hold them
	Applied
}

// union is a with b's units, data and managed paths added: a unit b has under
// the same path replaces a's.
func union(a Applied, managedA []string, b Applied, managedB []string) (Applied, []string) {
	out := Applied{Manifest: b.Manifest}
	seen := map[string]int{}
	for _, u := range append(append([]UnitFile{}, a.Units...), b.Units...) {
		if i, ok := seen[u.Path]; ok {
			out.Units[i] = u
			continue
		}
		seen[u.Path] = len(out.Units)
		out.Units = append(out.Units, u)
	}
	set := map[string]bool{}
	for _, d := range append(append([]string{}, a.Data...), b.Data...) {
		set[d] = true
	}
	out.Data = keys(set)
	roots := map[string]bool{}
	for _, r := range append(append([]string{}, a.Roots...), b.Roots...) {
		roots[r] = true
	}
	out.Roots = keys(roots)
	managed := map[string]bool{}
	for _, p := range append(append(append(append([]string{}, managedA...), managedB...), a.managed()...), b.managed()...) {
		managed[p] = true
	}
	return out, keys(managed)
}
