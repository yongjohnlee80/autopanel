package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FROM A STACK TO PODMAN UNITS. One Podman unit file (Quadlet) per container,
// one for the stack's network, one per named volume, all in the stack user's
// home. That user's systemd turns each into a service.

// unitDir is where a user's systemd looks for Podman unit files, relative to
// the user's home.
const unitDir = ".config/containers/systemd/"

// install is the section that has a unit start at boot. A service a person
// stopped is written without it, so a reboot does not start it.
const install = "\n[Install]\nWantedBy=default.target\n"

// Unit kinds.
const (
	KindContainer = "container"
	KindNetwork   = "network"
	KindVolume    = "volume"
)

// UnitFile is one unit of a stack, as it was applied.
type UnitFile struct {
	Path    string    `json:"path"`              // relative to the stack user's home
	Kind    string    `json:"kind"`              // KindContainer, KindNetwork, KindVolume
	Service string    `json:"service,omitempty"` // for a container
	Body    string    `json:"body"`              // the unit's text, with its [Install] section
	Image   string    `json:"image,omitempty"`   // as the compose file names it, fully qualified
	Digest  string    `json:"digest,omitempty"`  // what its last pull resolved
	Ports   []PortUse `json:"ports,omitempty"`   // the host ports it claims
	Inputs  []string  `json:"inputs,omitempty"`  // the managed paths it mounts or reads
	Needs   []string  `json:"needs,omitempty"`   // the services it depends on
	EnvSHA  string    `json:"env_sha,omitempty"` // of its generated environment file
}

// systemdName is the service a unit file becomes.
func (u UnitFile) systemdName() string { return ServiceUnit(u.Path) }

// ServiceUnit is the systemd service Podman makes of a unit file:
// "x.container" is "x.service", "x.volume" is "x-volume.service", and
// "x.network" is "x-network.service".
func ServiceUnit(file string) string {
	base := file[strings.LastIndex(file, "/")+1:]
	switch {
	case strings.HasSuffix(base, ".container"):
		return strings.TrimSuffix(base, ".container") + ".service"
	case strings.HasSuffix(base, ".volume"):
		return strings.TrimSuffix(base, ".volume") + "-volume.service"
	case strings.HasSuffix(base, ".network"):
		return strings.TrimSuffix(base, ".network") + "-network.service"
	}
	return base
}

func containerPath(stack, service string) string {
	return unitDir + stack + "-" + service + ".container"
}

// word writes one word of a unit's value: quoted, with what systemd and
// Podman's generator would read as their own ('\', '"', '%', '$') written so
// that the container gets the word as it is. A line break never reaches it:
// the parser refuses one.
func word(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '%', '$':
			b.WriteByte(c)
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// value writes a unit value of several words. No other function writes a
// value that came from the compose file as text.
func value(words ...string) string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = word(w)
	}
	return strings.Join(out, " ")
}

// whole writes a value that a key takes as one string, quotes and all: only
// the two characters systemd expands are doubled.
func whole(s string) string {
	return strings.NewReplacer("%", "%%", "$", "$$").Replace(s)
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// envFile is the generated environment file of a service: its variables that
// .env filled, which must not be on a command line. ok is false with none.
func envFile(stack string, s Spec) (File, bool) {
	var b strings.Builder
	for _, e := range s.Environment {
		if e.FromEnv {
			b.WriteString(e.Key + "=" + e.Value + "\n")
		}
	}
	if b.Len() == 0 {
		return File{}, false
	}
	return File{Path: "stack/" + Generated + "/" + s.Name + ".env", Mode: 0o400, Body: []byte(b.String())}, true
}

// inputs are the managed paths a service mounts or reads: a change to one of
// them is a change to what the container runs with.
func inputs(s Spec) []string {
	out := append([]string{}, s.EnvFile...)
	for _, m := range s.Volumes {
		if !m.Named && m.ReadOnly {
			out = append(out, m.Source)
		}
	}
	return out
}

// needsNetwork reports whether any service of the stack is on its private
// network.
func needsNetwork(st Stack) bool {
	for _, s := range st.Services {
		if !s.HostNetwork {
			return true
		}
	}
	return false
}

const written = "# Written by AutoPanel from the stack's compose file. Change that file and apply it: an apply writes this one again.\n"

// units renders a checked stack as its unit files, and the environment files
// the core generates for it. digests names each service's image by the digest
// its pull resolved.
func units(stack string, st Stack, digests map[string]string) ([]UnitFile, []File) {
	var out []UnitFile
	var gen []File
	if needsNetwork(st) {
		out = append(out, UnitFile{Path: unitDir + stack + ".network", Kind: KindNetwork,
			Body: written + "[Unit]\nDescription=AutoPanel stack " + stack + ", its network\n\n[Network]\nNetworkName=" + stack + "\n"})
	}
	for _, v := range st.Volumes {
		out = append(out, UnitFile{Path: unitDir + stack + "-" + v + ".volume", Kind: KindVolume,
			Body: written + "[Unit]\nDescription=AutoPanel stack " + stack + ", volume " + v + "\n\n[Volume]\nVolumeName=" + stack + "-" + v + "\n"})
	}
	for _, s := range st.Services {
		u := UnitFile{Path: containerPath(stack, s.Name), Kind: KindContainer, Service: s.Name,
			Image: s.Image, Digest: digests[s.Name], Inputs: inputs(s), Needs: s.DependsOn}
		for _, p := range s.Ports {
			u.Ports = append(u.Ports, p.Use())
		}
		env, has := envFile(stack, s)
		if has {
			gen = append(gen, env)
			u.EnvSHA = hash(env.Body)
		}
		u.Body = containerUnit(stack, s, digests[s.Name], has)
		out = append(out, u)
	}
	return out, gen
}

// containerUnit renders one container's unit file.
func containerUnit(stack string, s Spec, digest string, generatedEnv bool) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	b.WriteString(written)
	line("[Unit]\nDescription=AutoPanel stack %s, service %s", stack, s.Name)
	for _, d := range s.DependsOn {
		line("Requires=%s-%s.service\nAfter=%s-%s.service", stack, d, stack, d)
	}
	// A unit that cannot start yet (the address it binds is not there after a
	// boot) is tried again for as long as it takes: systemd's start limit
	// would otherwise leave it failed.
	line("StartLimitIntervalSec=0\n\n[Container]")
	repo, pick := ImageRef(s.Image)
	if digest != "" {
		pick = "@" + digest
	}
	line("Image=%s%s", repo, pick)
	line("ContainerName=%s-%s", stack, s.Name)
	if len(s.Command) > 0 {
		line("Exec=%s", value(s.Command...))
	}
	if len(s.Entrypoint) > 0 {
		j, _ := json.Marshal(s.Entrypoint)
		line("PodmanArgs=%s", word("--entrypoint="+string(j)))
	}
	for _, e := range s.Environment {
		if !e.FromEnv {
			line("Environment=%s", word(e.Key+"="+e.Value))
		}
	}
	if generatedEnv {
		line("EnvironmentFile=%%h/stack/%s/%s.env", Generated, s.Name)
	}
	for _, f := range s.EnvFile {
		line("EnvironmentFile=%%h/stack/%s", f)
	}
	if s.HostNetwork {
		// Nothing is published on the host's network: the service's ports are
		// whatever it listens on, and its "ports" only declare them.
		line("Network=host")
	} else {
		for _, p := range s.Ports {
			line("PublishPort=%s", publish(p))
		}
		line("Network=%s.network\nPodmanArgs=--network-alias=%s", stack, s.Name)
	}
	for _, m := range s.Volumes {
		src := "%h/stack/" + m.Source
		if m.Named {
			src = stack + "-" + m.Source + ".volume"
		}
		if m.ReadOnly {
			line("Volume=%s:%s:ro", src, m.Target)
		} else {
			line("Volume=%s:%s", src, m.Target)
		}
	}
	if s.HasUser {
		// The container's user is the stack's user on the host: what it writes
		// is that user's, and the host's listings name the stack.
		line("User=%d\nGroup=%d\nUserNS=keep-id:uid=%d,gid=%d", s.UID, s.GID, s.UID, s.GID)
	}
	if s.ReadOnly {
		line("ReadOnly=true")
	}
	for _, c := range s.CapDrop {
		line("DropCapability=%s", c)
	}
	for _, c := range s.CapAdd {
		line("AddCapability=%s", c)
	}
	for _, t := range s.Tmpfs {
		line("Tmpfs=%s", t)
	}
	if s.WorkingDir != "" {
		line("WorkingDir=%s", s.WorkingDir)
	}
	if s.Hostname != "" {
		line("HostName=%s", s.Hostname)
	}
	line("NoNewPrivileges=true")
	if h := s.Health; h != nil {
		switch h.Kind {
		case "none":
			line("HealthCmd=none")
		case "exec":
			// The list without its "CMD" word: Podman puts that back itself, and
			// reads a list that keeps it as one word.
			j, _ := json.Marshal(h.Args)
			line("HealthCmd=%s", whole(string(j)))
		case "shell":
			line("HealthCmd=%s", whole(h.Shell))
		}
		if h.Kind != "none" {
			if h.Interval != "" {
				line("HealthInterval=%s", h.Interval)
			}
			if h.Timeout != "" {
				line("HealthTimeout=%s", h.Timeout)
			}
			if h.StartPeriod != "" {
				line("HealthStartPeriod=%s", h.StartPeriod)
			}
			if h.Retries > 0 {
				line("HealthRetries=%d", h.Retries)
			}
		}
	}
	restart := s.Restart
	if restart == "unless-stopped" {
		restart = "always"
	}
	line("\n[Service]\nRestart=%s\nRestartSec=10\nTimeoutStartSec=600", restart)
	if s.MemLimit > 0 {
		line("MemoryMax=%d\nMemorySwapMax=0", s.MemLimit)
	}
	b.WriteString(install)
	return b.String()
}

// publish writes one PublishPort value.
func publish(p Publish) string {
	ports := strconv.Itoa(p.HostFrom) + ":" + strconv.Itoa(p.ContFrom)
	if p.HostFrom != p.HostTo {
		ports = fmt.Sprintf("%d-%d:%d-%d", p.HostFrom, p.HostTo, p.ContFrom, p.ContTo)
	}
	switch {
	case !p.Addr.IsValid():
	case p.Addr.Is6():
		ports = "[" + p.Addr.String() + "]:" + ports
	default:
		ports = p.Addr.String() + ":" + ports
	}
	return ports + "/" + p.Proto
}

// withoutInstall is a unit's text for a service that stays stopped across a
// boot.
func withoutInstall(body string) string { return strings.TrimSuffix(body, install) }
