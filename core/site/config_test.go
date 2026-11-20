package site

import (
	"errors"
	"strings"
	"testing"
)

func TestAGoodConfiguration(t *testing.T) {
	c, err := ParseConfig(`
title: Example
tagline: Notes on things
language: pt-BR
theme: docs
home: about
nav:
  - {label: Articles, to: /articles/}
  - {label: Elsewhere, to: "https://example.org/x?y=1"}
footer: "© Example"
look:
  accent: "#0b6e4f"
  background: "#FFFFFF"
  text: "#1a1a1a"
  font: serif
  width: narrow
  logo: logo.png
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Theme != "docs" || c.Home != "about" || len(c.Nav) != 2 || c.Look.Logo != "logo.png" {
		t.Fatalf("%+v", c)
	}
	// stored as JSON, markup escaped, and read back the same
	j := c.JSON()
	back, err := StoredConfig(Site{Host: "x.example", Config: j})
	if err != nil || back.Title != c.Title || back.Nav[1].To != c.Nav[1].To {
		t.Fatalf("%s: %+v, %v", j, back, err)
	}
}

func TestAConfigurationsDefaults(t *testing.T) {
	c, err := ParseConfig("title: T\n")
	if err != nil || c.Language != "en" || c.Theme != "journal" || c.Home != "latest" {
		t.Fatalf("%+v, %v", c, err)
	}
	c, err = StoredConfig(Site{Host: "blog.example.com"})
	if err != nil || c.Title != "blog.example.com" {
		t.Fatalf("a site never set: %+v, %v", c, err)
	}
}

// Every refusal is ErrBadConfig, and says which key.
func TestABadConfigurationIsRefused(t *testing.T) {
	cases := map[string]struct{ src, says string }{
		"no title":                 {"tagline: x\n", "title"},
		"an unknown key":           {"title: T\nscript: x\n", "script"},
		"an unknown look key":      {"title: T\nlook: {css: 'body{}'}\n", "css"},
		"an unknown theme":         {"title: T\ntheme: ../../etc\n", "theme"},
		"a colour that is not one": {"title: T\nlook: {accent: 'red;}body{x:y'}\n", "look.accent"},
		"a colour by name":         {"title: T\nlook: {text: red}\n", "look.text"},
		"a font of its own":        {"title: T\nlook: {font: 'Comic Sans'}\n", "look.font"},
		"a width":                  {"title: T\nlook: {width: 100%}\n", "look.width"},
		"a logo path":              {"title: T\nlook: {logo: ../secret.png}\n", "look.logo"},
		"a logo that is svg":       {"title: T\nlook: {logo: logo.svg}\n", "look.logo"},
		"a logo address":           {"title: T\nlook: {logo: 'https://x/l.png'}\n", "look.logo"},
		"a javascript link":        {"title: T\nnav: [{label: x, to: 'javascript:alert(1)'}]\n", "nav[0].to"},
		"an http link":             {"title: T\nnav: [{label: x, to: 'http://x.example/'}]\n", "nav[0].to"},
		"a protocol-relative link": {"title: T\nnav: [{label: x, to: '//evil.example/'}]\n", "nav[0].to"},
		"a link with credentials":  {"title: T\nnav: [{label: x, to: 'https://a:b@x.example/'}]\n", "nav[0].to"},
		"a relative link":          {"title: T\nnav: [{label: x, to: 'about/'}]\n", "nav[0].to"},
		"a link with a quote":      {"title: T\nnav: [{label: x, to: '/a\"onmouseover=x'}]\n", "nav[0].to"},
		"a label missing":          {"title: T\nnav: [{to: /a/}]\n", "nav[0]"},
		"a title too long":         {"title: " + strings.Repeat("x", 121) + "\n", "title"},
		"a title with a newline":   {"title: \"a\\nb\"\n", "title"},
		"a language":               {"title: T\nlanguage: 'en\"><x'\n", "language"},
		"home a path":              {"title: T\nhome: /etc/passwd\n", "home"},
		"two documents":            {"title: T\n---\ntitle: U\n", "more than one"},
		"an alias":                 {"title: &a T\ntagline: *a\n", "alias"},
		"an alias bomb":            {"a: &a [x, x]\nb: &b [*a, *a]\ntitle: T\n", "alias"},
		"too many links":           {"title: T\nnav: [" + strings.Repeat("{label: x, to: /x/},", 13) + "]\n", "nav"},
		"too large":                {"title: T\nfooter: " + strings.Repeat("x", MaxConfigBytes) + "\n", "larger"},
		"not YAML":                 {"title: [\n", ""},
		"empty":                    {"", "empty"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(tc.src)
			var d interface{ PublicDetail() string }
			if !errors.Is(err, ErrBadConfig) || !errors.As(err, &d) || !strings.Contains(d.PublicDetail(), tc.says) {
				t.Fatalf("%v", err)
			}
		})
	}
}
