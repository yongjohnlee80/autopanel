package site

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// inertPage is the name an .html document's cleaned copy is built as: shown
// in a frame with sandbox="", so its own styles are allowed and nothing else
// more than a page's.
const inertPage = "_doc.html"

// Elements no page may hold. A page is HTML and CSS: the kit's two diagram
// scripts and the frames of section 5 are the exceptions, checked on their
// own below.
var deniedElements = map[string]bool{
	"object": true, "embed": true, "applet": true, "param": true,
	"base": true, "form": true,
	"frame": true, "frameset": true, "portal": true, "fencedframe": true,
	"template": true, "noscript": true, "noembed": true, "noframes": true,
	"audio": true, "video": true, "track": true,
}

// The rel values a <link> may have; every one but these is refused, so
// nothing preloads, preconnects or prefetches from anywhere.
var (
	linkLoads    = map[string]bool{"stylesheet": true, "icon": true, "apple-touch-icon": true}
	linkNavigate = map[string]bool{"canonical": true, "alternate": true, "sitemap": true, "next": true, "prev": true, "author": true, "license": true, "me": true, "shortcut": true}
)

// Attributes whose value the browser fetches: a path of this site only.
var loadingAttrs = map[string]bool{"src": true, "srcset": true, "imagesrcset": true, "poster": true, "background": true, "data": true}

// Attributes whose value is a place a reader goes: relative, http, https or
// mailto.
var navigatingAttrs = map[string]bool{"href": true, "cite": true, "longdesc": true, "action": true}

// Attributes no element may have, whatever its value.
var deniedAttrs = map[string]bool{"srcdoc": true, "formaction": true, "ping": true, "http-equiv": true}

func (c *checker) checkHTML(rel string, data []byte) error {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return refuse(rel, "%v", err)
	}
	p := pageCheck{c: c, rel: rel, inert: path.Base(rel) == inertPage}
	if p.inert {
		p.mermaid = false
	} else if c.opt.Mermaid != nil {
		p.mermaid = c.opt.Mermaid(rel)
	}
	if err := p.node(doc); err != nil {
		return refuse(rel, "%v", err)
	}
	return nil
}

type pageCheck struct {
	c       *checker
	rel     string
	inert   bool // a _doc.html: its own styles allowed
	mermaid bool // the renderer said this page has a diagram
	scripts map[string]bool
}

func (p *pageCheck) node(n *html.Node) error {
	if n.Type == html.ElementNode {
		var err error
		switch n.Namespace {
		case "":
			err = p.element(n)
		case "svg":
			err = svgElement(n)
		default:
			err = fmt.Errorf("a <%s> element (%s)", n.Data, n.Namespace)
		}
		if err != nil {
			return err
		}
		if n.Namespace == "" && n.Data == "style" {
			return nil // its text was checked as CSS
		}
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if err := p.node(ch); err != nil {
			return err
		}
	}
	return nil
}

func (p *pageCheck) element(n *html.Node) error {
	name := n.Data
	if deniedElements[name] {
		return fmt.Errorf("a <%s> element", name)
	}
	switch name {
	case "input":
		return checkbox(n)
	case "script":
		return p.script(n)
	case "iframe":
		return p.iframe(n)
	case "style":
		if !p.inert {
			return errors.New("a <style> element")
		}
		var css strings.Builder
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			if ch.Type == html.TextNode {
				css.WriteString(ch.Data)
			}
		}
		if err := checkCSS(css.String()); err != nil {
			return fmt.Errorf("<style>: %w", err)
		}
	case "meta":
		// http-equiv is among deniedAttrs: no refresh, no policy of the page's own
	case "link":
		if err := p.link(n); err != nil {
			return err
		}
	}
	return p.attrs(n)
}

func (p *pageCheck) attrs(n *html.Node) error {
	for _, a := range n.Attr {
		key := a.Key
		switch {
		case a.Namespace != "":
			return fmt.Errorf("<%s> has an attribute %s:%s", n.Data, a.Namespace, key)
		case strings.HasPrefix(key, "on"):
			return fmt.Errorf("<%s> has an event attribute %s", n.Data, key)
		case deniedAttrs[key]:
			return fmt.Errorf("<%s> has a %s attribute", n.Data, key)
		case key == "style":
			if !p.inert {
				return fmt.Errorf("<%s> has a style attribute", n.Data)
			}
			if err := checkCSS(a.Val); err != nil {
				return fmt.Errorf("<%s style>: %w", n.Data, err)
			}
		case key == "srcset" || key == "imagesrcset":
			for _, u := range srcsetURLs(a.Val) {
				if !localURL(u) {
					return fmt.Errorf("<%s %s> loads %q, which is not a path of this site", n.Data, key, u)
				}
			}
		case loadingAttrs[key]:
			if !localURL(a.Val) {
				return fmt.Errorf("<%s %s> loads %q, which is not a path of this site", n.Data, key, a.Val)
			}
		case navigatingAttrs[key]:
			if n.Data == "link" {
				continue // link checks its own href by its rel
			}
			if !navigableURL(a.Val) {
				return fmt.Errorf("<%s %s> goes to %q: only a path of this site, http, https or mailto", n.Data, key, a.Val)
			}
		}
	}
	return nil
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func (p *pageCheck) link(n *html.Node) error {
	rel, _ := attr(n, "rel")
	href, _ := attr(n, "href")
	loads := false
	for _, r := range strings.Fields(strings.ToLower(rel)) {
		switch {
		case linkLoads[r]:
			loads = true
		case linkNavigate[r]:
		default:
			return fmt.Errorf("a <link rel=%q>", r)
		}
	}
	if loads && !localURL(href) {
		return fmt.Errorf("<link rel=%q> loads %q, which is not a path of this site", rel, href)
	}
	if !loads && href != "" && !navigableURL(href) {
		return fmt.Errorf("<link rel=%q> goes to %q", rel, href)
	}
	return nil
}

// checkbox allows the one input a page has: a task list's item, a checkbox
// that is disabled, with nothing that sends or loads. Any other input fails.
func checkbox(n *html.Node) error {
	typ, _ := attr(n, "type")
	_, disabled := attr(n, "disabled")
	if !strings.EqualFold(typ, "checkbox") || !disabled {
		return errors.New("an <input> that is not a disabled checkbox")
	}
	for _, a := range n.Attr {
		if a.Namespace != "" || (a.Key != "type" && a.Key != "disabled" && a.Key != "checked" && a.Key != "class") {
			return fmt.Errorf("an <input> with a %s attribute", a.Key)
		}
	}
	return nil
}

// script allows the kit's two diagram scripts, exactly, on a page the renderer
// said has a diagram, each once. Anything else is a failed build.
func (p *pageCheck) script(n *html.Node) error {
	if !p.mermaid {
		return errors.New("a <script> element")
	}
	if n.FirstChild != nil {
		return errors.New("a <script> with text of its own")
	}
	src, _ := attr(n, "src")
	integrity, _ := attr(n, "integrity")
	for _, a := range n.Attr {
		if a.Namespace != "" || (a.Key != "src" && a.Key != "integrity" && a.Key != "defer") {
			return fmt.Errorf("a <script> with a %s attribute", a.Key)
		}
	}
	if _, ok := attr(n, "defer"); !ok {
		return errors.New("a <script> that is not deferred")
	}
	for _, k := range p.c.opt.KitScripts {
		if src == k.Path && integrity == k.Integrity && integrity != "" {
			if p.scripts[src] {
				return fmt.Errorf("the script %s twice", src)
			}
			if p.scripts == nil {
				p.scripts = map[string]bool{}
			}
			p.scripts[src] = true
			return nil
		}
	}
	return fmt.Errorf("a <script src=%q> that is not one of the kit's, with its integrity", src)
}

// iframe allows the two frames section 5 makes: a document's inert copy beside
// its page, sandboxed with nothing allowed; and an active document on the
// content host, allowed scripts and nothing else.
func (p *pageCheck) iframe(n *html.Node) error {
	sandbox, ok := attr(n, "sandbox")
	if !ok {
		return errors.New("an <iframe> without a sandbox")
	}
	for _, a := range n.Attr {
		switch {
		case a.Namespace != "":
			return fmt.Errorf("an <iframe> with an attribute %s:%s", a.Namespace, a.Key)
		case a.Key == "src" || a.Key == "sandbox" || a.Key == "title" || a.Key == "loading" ||
			a.Key == "width" || a.Key == "height" || a.Key == "class" || a.Key == "referrerpolicy":
		default:
			return fmt.Errorf("an <iframe> with a %s attribute", a.Key)
		}
	}
	src, _ := attr(n, "src")
	src = stripURL(src)
	if src == inertPage || src == "./"+inertPage {
		if sandbox != "" {
			return fmt.Errorf("the inert document's frame allows %q", sandbox)
		}
		if !p.c.exists(path.Join(path.Dir(p.rel), inertPage)) {
			return errors.New("a frame of an inert document the build did not make")
		}
		return nil
	}
	if p.c.opt.ContentHost != "" {
		if u, err := url.Parse(src); err == nil && u.Scheme == "https" && u.Host == p.c.opt.ContentHost && u.User == nil {
			if sandbox != "allow-scripts" {
				return fmt.Errorf("an active document's frame allows %q", sandbox)
			}
			return nil
		}
	}
	return fmt.Errorf("an <iframe> of %q", src)
}

// stripURL removes what a browser removes before it reads an address: spaces
// and controls at either end, and tabs and newlines anywhere.
func stripURL(s string) string {
	s = strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 })
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

// scheme is the address's scheme in lower case, or "" for a relative one.
func scheme(s string) string {
	for i, r := range s {
		switch {
		case r == ':':
			if i == 0 {
				return ""
			}
			return strings.ToLower(s[:i])
		case r == '/' || r == '?' || r == '#':
			return ""
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return ""
		}
	}
	return ""
}

// localURL: a path of this site, or a fragment. Never another host, not even
// by "//host" or a backslash a browser reads as a slash.
func localURL(s string) bool {
	s = stripURL(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, "\\") || strings.HasPrefix(s, "//") {
		return false
	}
	if i := strings.IndexByte(s, ':'); i >= 0 && !strings.ContainsAny(s[:i], "/?#") {
		return false // a colon before any slash, ? or #: a scheme, whatever its spelling
	}
	return true
}

// navigableURL: a path of this site, or an http, https or mailto address.
func navigableURL(s string) bool {
	s = stripURL(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return true
	}
	switch scheme(s) {
	case "http", "https", "mailto":
		return !strings.Contains(s, "\\")
	}
	return localURL(s)
}

// srcsetURLs are the addresses in a srcset: each candidate is an address and
// an optional descriptor, separated by commas.
func srcsetURLs(s string) []string {
	var out []string
	for _, cand := range strings.Split(s, ",") {
		f := strings.Fields(cand)
		if len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// The SVG a page may hold inline: exactly what golib's chart writer emits
// (gui/svgcanvas.go: a chart's shapes, its clips and gradients, its labels),
// and the plain shapes beside them. No script, foreignObject, use, image, a,
// animation, style or title (an integration point back into HTML).
var (
	svgElements = map[string]bool{
		"svg": true, "defs": true, "clipPath": true, "linearGradient": true, "stop": true, "g": true,
		"rect": true, "ellipse": true, "circle": true, "line": true, "path": true, "polygon": true, "polyline": true,
		"text": true,
	}
	svgAttrs = map[string]bool{
		"viewBox": true, "width": true, "height": true, "x": true, "y": true, "preserveAspectRatio": true,
		"id": true, "clip-path": true, "transform": true, "opacity": true,
		"rx": true, "ry": true, "cx": true, "cy": true, "r": true, "d": true, "points": true,
		"x1": true, "y1": true, "x2": true, "y2": true, "gradientUnits": true, "offset": true,
		"fill": true, "fill-opacity": true, "stroke": true, "stroke-width": true, "stroke-opacity": true,
		"stop-color": true, "stop-opacity": true,
		"font-family": true, "font-size": true, "font-weight": true, "font-style": true,
		"class": true, "role": true, "aria-label": true,
	}
	svgFragmentURL = regexp.MustCompile(`^url\(#[A-Za-z0-9_-]+\)$`)
)

const svgNamespace = "http://www.w3.org/2000/svg"

func svgElement(n *html.Node) error {
	if !svgElements[n.Data] {
		return fmt.Errorf("an <%s> element in an SVG", n.Data)
	}
	for _, a := range n.Attr {
		switch {
		case a.Namespace == "" && a.Key == "xmlns":
			if a.Val != svgNamespace {
				return fmt.Errorf("an SVG of namespace %q", a.Val)
			}
			continue
		case a.Namespace == "xml" && a.Key == "space":
			continue
		case a.Namespace != "" || !svgAttrs[a.Key]:
			return fmt.Errorf("<%s> in an SVG has a %s attribute", n.Data, qualified(a))
		}
		v := strings.ToLower(strings.Join(strings.Fields(a.Val), ""))
		if strings.Contains(v, "url(") && !svgFragmentURL.MatchString(v) {
			return fmt.Errorf("<%s %s> refers to %q: only a fragment of the same drawing", n.Data, a.Key, a.Val)
		}
		if strings.Contains(v, "javascript:") || strings.Contains(v, "data:") {
			return fmt.Errorf("<%s %s> holds an address", n.Data, a.Key)
		}
	}
	return nil
}

func qualified(a html.Attribute) string {
	if a.Namespace == "" {
		return a.Key
	}
	return a.Namespace + ":" + a.Key
}

// checkCSS refuses an @import and any url() that is not a path of this site,
// and the functions that load without url(). It reads the stylesheet as CSS
// does: comments skipped, strings and escapes decoded, so "@\69mport" is an
// @import.
func checkCSS(s string) error {
	t := cssTokens{s: s}
	for {
		kind, val, err := t.next()
		if err != nil {
			return err
		}
		switch kind {
		case cssEOF:
			return nil
		case cssAt:
			if strings.EqualFold(val, "import") {
				return errors.New("an @import")
			}
		case cssURL:
			if !localURL(val) {
				return fmt.Errorf("url(%q) is not a path of this site", val)
			}
		case cssFunction:
			switch strings.ToLower(val) {
			case "image-set", "-webkit-image-set", "image", "src", "element", "-moz-element", "expression", "cross-fade", "-webkit-cross-fade":
				return fmt.Errorf("the function %s()", val)
			}
		case cssIdent:
			switch strings.ToLower(val) {
			case "behavior", "-moz-binding":
				return fmt.Errorf("the property %s", val)
			}
		}
	}
}

type cssKind int

const (
	cssEOF cssKind = iota
	cssAt
	cssURL
	cssFunction
	cssIdent
	cssOther
)

type cssTokens struct {
	s string
	i int
}

func (t *cssTokens) next() (cssKind, string, error) {
	for t.i < len(t.s) {
		ch := t.s[t.i]
		switch {
		case strings.HasPrefix(t.s[t.i:], "/*"):
			end := strings.Index(t.s[t.i+2:], "*/")
			if end < 0 {
				return cssEOF, "", nil
			}
			t.i += 2 + end + 2
		case ch == '"' || ch == '\'':
			if _, err := t.str(ch); err != nil {
				return 0, "", err
			}
			return cssOther, "", nil
		case ch == '@':
			t.i++
			return cssAt, t.ident(), nil
		case identStart(t.s, t.i):
			name := t.ident()
			if t.i < len(t.s) && t.s[t.i] == '(' {
				t.i++
				if strings.EqualFold(name, "url") {
					u, err := t.url()
					return cssURL, u, err
				}
				return cssFunction, name, nil
			}
			return cssIdent, name, nil
		default:
			t.i++
		}
	}
	return cssEOF, "", nil
}

func identStart(s string, i int) bool {
	c := s[i]
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c >= 0x80:
		return true
	case c == '\\':
		return i+1 < len(s) && s[i+1] != '\n'
	case c == '-':
		return i+1 < len(s) && (identStart(s, i+1) || s[i+1] == '-')
	}
	return false
}

func (t *cssTokens) ident() string {
	var b strings.Builder
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c >= 0x80:
			b.WriteByte(c)
			t.i++
		case c == '\\' && t.i+1 < len(t.s) && t.s[t.i+1] != '\n':
			t.i++
			b.WriteString(t.escape())
		default:
			return b.String()
		}
	}
	return b.String()
}

// escape reads what follows a backslash: up to six hex digits and one space,
// or one character as itself.
func (t *cssTokens) escape() string {
	j := t.i
	for j < len(t.s) && j-t.i < 6 && isHex(t.s[j]) {
		j++
	}
	if j == t.i {
		r := t.s[t.i]
		t.i++
		return string(r)
	}
	var v rune
	fmt.Sscanf(t.s[t.i:j], "%x", &v)
	t.i = j
	if t.i < len(t.s) && (t.s[t.i] == ' ' || t.s[t.i] == '\t' || t.s[t.i] == '\n') {
		t.i++
	}
	if v == 0 || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff) {
		v = 0xfffd
	}
	return string(v)
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (t *cssTokens) str(q byte) (string, error) {
	t.i++
	var b strings.Builder
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == q:
			t.i++
			return b.String(), nil
		case c == '\n':
			return b.String(), nil // a bad string: CSS ends it here
		case c == '\\' && t.i+1 < len(t.s):
			t.i++
			if t.s[t.i] == '\n' {
				t.i++
				continue
			}
			b.WriteString(t.escape())
		default:
			b.WriteByte(c)
			t.i++
		}
	}
	return b.String(), nil
}

// url reads url( … ) after its parenthesis: a string, or the bare address.
func (t *cssTokens) url() (string, error) {
	for t.i < len(t.s) && strings.IndexByte(" \t\n\r\f", t.s[t.i]) >= 0 {
		t.i++
	}
	if t.i < len(t.s) && (t.s[t.i] == '"' || t.s[t.i] == '\'') {
		return t.str(t.s[t.i])
	}
	var b strings.Builder
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == ')':
			t.i++
			return strings.TrimSpace(b.String()), nil
		case c == '\\' && t.i+1 < len(t.s):
			t.i++
			b.WriteString(t.escape())
		default:
			b.WriteByte(c)
			t.i++
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// The feed and the sitemap: well formed, no document type (so no entity),
// no processing instruction but the declaration, no stylesheet, and no
// element outside RSS, Atom and the sitemap protocol.
var (
	xmlSpaces = map[string]bool{
		"": true, "http://www.w3.org/2005/Atom": true, "http://www.sitemaps.org/schemas/sitemap/0.9": true,
		"http://purl.org/dc/elements/1.1/": true, "http://purl.org/rss/1.0/modules/content/": true,
	}
	xmlElements = map[string]bool{
		// RSS 2.0
		"rss": true, "channel": true, "title": true, "link": true, "description": true, "language": true,
		"copyright": true, "managingEditor": true, "webMaster": true, "pubDate": true, "lastBuildDate": true,
		"category": true, "generator": true, "docs": true, "ttl": true, "image": true, "url": true,
		"width": true, "height": true, "item": true, "author": true, "guid": true, "creator": true, "encoded": true,
		// Atom
		"feed": true, "entry": true, "id": true, "updated": true, "published": true, "summary": true,
		"content": true, "name": true, "email": true, "uri": true, "subtitle": true, "rights": true,
		"icon": true, "logo": true,
		// sitemaps
		"urlset": true, "loc": true, "lastmod": true, "changefreq": true, "priority": true,
		"sitemapindex": true, "sitemap": true,
	}
)

func checkXML(data []byte) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	first := true
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch tok := tok.(type) {
		case xml.ProcInst:
			if tok.Target != "xml" || !first {
				return fmt.Errorf("the instruction <?%s?>", tok.Target)
			}
		case xml.Directive:
			return errors.New("a document type or another directive")
		case xml.StartElement:
			if !xmlSpaces[tok.Name.Space] || !xmlElements[tok.Name.Local] {
				return fmt.Errorf("the element <%s> (%s)", tok.Name.Local, tok.Name.Space)
			}
		}
		if _, ok := tok.(xml.CharData); !ok {
			first = false
		}
	}
}
