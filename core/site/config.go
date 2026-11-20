package site

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Config is a site's configuration: what its pages say of themselves and how
// they look. It is validated whole before it is stored, and a refused one
// changes nothing. Nothing in it is markup, and nothing can leave the value it
// is put in: a colour is a colour, a font one of three words.
type Config struct {
	Title    string    `yaml:"title" json:"title"`
	Tagline  string    `yaml:"tagline,omitempty" json:"tagline,omitempty"`
	Language string    `yaml:"language,omitempty" json:"language"`
	Theme    string    `yaml:"theme,omitempty" json:"theme"`
	Home     string    `yaml:"home,omitempty" json:"home"` // "latest", or the slug of a page shown as the home page
	Nav      []NavLink `yaml:"nav,omitempty" json:"nav,omitempty"`
	Footer   string    `yaml:"footer,omitempty" json:"footer,omitempty"`
	Look     Look      `yaml:"look,omitempty" json:"look"`
}

// NavLink is one entry of the site's navigation.
type NavLink struct {
	Label string `yaml:"label" json:"label"`
	To    string `yaml:"to" json:"to"` // a path of this site, or an https:// address
}

// Look is the site's look without a theme of its own: each value becomes a
// CSS variable.
type Look struct {
	Accent     string `yaml:"accent,omitempty" json:"accent,omitempty"`
	Background string `yaml:"background,omitempty" json:"background,omitempty"`
	Text       string `yaml:"text,omitempty" json:"text,omitempty"`
	Font       string `yaml:"font,omitempty" json:"font,omitempty"`   // serif, sans or mono: the kit's own
	Width      string `yaml:"width,omitempty" json:"width,omitempty"` // narrow or wide
	Logo       string `yaml:"logo,omitempty" json:"logo,omitempty"`   // the plain name of an image
}

// The kit's themes. A theme of the owner's is a later step.
var Themes = []string{"journal", "docs"}

// The bounds of a configuration.
const (
	MaxConfigBytes = 16 << 10
	maxTitle       = 120
	maxLine        = 200 // a tagline, a footer
	maxLabel       = 40
	maxNav         = 12
	maxTo          = 200
)

// ErrBadConfig is a configuration refused; the detail says which key and why.
var ErrBadConfig = errors.New("site: the configuration was refused")

func badConfig(format string, a ...any) error {
	return &configError{detail: fmt.Sprintf(format, a...)}
}

type configError struct{ detail string }

func (e *configError) Error() string        { return ErrBadConfig.Error() + ": " + e.detail }
func (e *configError) Unwrap() error        { return ErrBadConfig }
func (e *configError) PublicDetail() string { return e.detail }

var (
	colour   = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	language = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$`)
	logoName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}\.(png|jpg|jpeg|webp|gif)$`)
)

// ParseConfig reads a configuration written in YAML, refusing an unknown
// key, a second document and an alias (so a small file cannot expand), and
// validates it. The result has its defaults filled in.
func ParseConfig(src string) (Config, error) {
	if len(src) > MaxConfigBytes {
		return Config{}, badConfig("larger than %d bytes", MaxConfigBytes)
	}
	if !utf8.ValidString(src) {
		return Config{}, badConfig("not UTF-8")
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return Config{}, badConfig("%s", yamlError(err))
	}
	if err := noAlias(&root); err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(strings.NewReader(src))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, badConfig("empty")
		}
		return Config{}, badConfig("%s", yamlError(err))
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return Config{}, badConfig("more than one document")
	}
	return c, c.Validate()
}

func yamlError(err error) string {
	s := strings.TrimPrefix(err.Error(), "yaml: ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func noAlias(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return badConfig("an anchor or an alias")
	}
	for _, c := range n.Content {
		if err := noAlias(c); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks every value, and fills in the defaults: language "en",
// theme "journal", home "latest".
func (c *Config) Validate() error {
	if c.Title == "" {
		return badConfig("title is required")
	}
	for _, f := range []struct {
		key, val string
		max      int
	}{{"title", c.Title, maxTitle}, {"tagline", c.Tagline, maxLine}, {"footer", c.Footer, maxLine}} {
		if err := plainText(f.key, f.val, f.max); err != nil {
			return err
		}
	}
	if c.Language == "" {
		c.Language = "en"
	}
	if !language.MatchString(c.Language) {
		return badConfig("language is a language tag, such as en or pt-BR")
	}
	if c.Theme == "" {
		c.Theme = "journal"
	}
	if !contains(Themes, c.Theme) {
		return badConfig("theme is one of %s", strings.Join(Themes, ", "))
	}
	if c.Home == "" {
		c.Home = "latest"
	}
	if c.Home != "latest" && !validName(c.Home, MaxSlug) {
		return badConfig("home is latest, or the slug of a page")
	}
	if len(c.Nav) > maxNav {
		return badConfig("nav has at most %d entries", maxNav)
	}
	for i, n := range c.Nav {
		if n.Label == "" {
			return badConfig("nav[%d] has no label", i)
		}
		if err := plainText(fmt.Sprintf("nav[%d].label", i), n.Label, maxLabel); err != nil {
			return err
		}
		if !navTarget(n.To) {
			return badConfig("nav[%d].to is a path of this site or an https:// address", i)
		}
	}
	for _, f := range []struct{ key, val string }{{"accent", c.Look.Accent}, {"background", c.Look.Background}, {"text", c.Look.Text}} {
		if f.val != "" && !colour.MatchString(f.val) {
			return badConfig("look.%s is a colour: # and six hexadecimal digits", f.key)
		}
	}
	if c.Look.Font != "" && !contains([]string{"serif", "sans", "mono"}, c.Look.Font) {
		return badConfig("look.font is serif, sans or mono")
	}
	if c.Look.Width != "" && !contains([]string{"narrow", "wide"}, c.Look.Width) {
		return badConfig("look.width is narrow or wide")
	}
	if c.Look.Logo != "" && !logoName.MatchString(c.Look.Logo) {
		return badConfig("look.logo is the plain name of a PNG, JPEG, WebP or GIF image")
	}
	return nil
}

// plainText: printable text on one line, of at most max characters.
func plainText(key, s string, max int) error {
	if utf8.RuneCountInString(s) > max {
		return badConfig("%s is at most %d characters", key, max)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) && r != ' ' {
			return badConfig("%s holds a character that is not printable", key)
		}
	}
	return nil
}

// navTarget: a path of this site (a slash and then no second one, no
// backslash, no space or control) or an https:// address with a host and no
// credentials.
func navTarget(to string) bool {
	if to == "" || len(to) > maxTo {
		return false
	}
	for _, r := range to {
		if r <= ' ' || r == 0x7f || r == '\\' || r == '"' || r == '<' || r == '>' {
			return false
		}
	}
	if strings.HasPrefix(to, "/") {
		return !strings.HasPrefix(to, "//")
	}
	u, err := url.Parse(to)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// JSON is the configuration as it is stored and given to the builder.
func (c Config) JSON() string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(c)
	return strings.TrimSpace(b.String())
}

// StoredConfig reads a configuration the store holds; "" is the default one,
// titled by the site's host.
func StoredConfig(s Site) (Config, error) {
	if s.Config == "" {
		c := Config{Title: s.Host}
		return c, c.Validate()
	}
	var c Config
	if err := json.Unmarshal([]byte(s.Config), &c); err != nil {
		return Config{}, err
	}
	return c, c.Validate()
}
