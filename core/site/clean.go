package site

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// CleanHTML makes an .html document's inert copy: a whole page holding what
// of the document is text, structure, tables, images of this site and its own
// styles, and nothing that acts. It keeps by a list, so an element or an
// attribute it does not know is not kept:
//
//   - a script, a frame, an object, a form's controls, audio and video, SVG and
//     MathML, a <link>, a <meta> and a <base> are removed with what they hold;
//   - any other element it does not know is removed and what it holds is kept;
//   - an event attribute, and every attribute not listed for its element, is
//     removed;
//   - a link keeps its address only when it is a place in the document itself
//     (#…): the copy is shown in a frame that may go nowhere, so any other
//     address is moved to the link's title, where a reader can read it;
//   - an image keeps its address only when it is a path of this site;
//   - a style sheet or a style attribute is kept only when the output check's
//     own rule for CSS passes it (no @import, no address outside this site).
//
// The output check reads the copy again as it reads any page, and the frame
// that shows it allows nothing (sandbox=""), so what this misses still cannot
// run. title is the document's <title>, for the frame.
func CleanHTML(src []byte) (page []byte, title string, err error) {
	doc, err := html.Parse(bytes.NewReader(src))
	if err != nil {
		return nil, "", err
	}
	c := cleaner{}
	body := &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body}
	c.walk(doc, body, 0)

	root := &html.Node{Type: html.DocumentNode}
	root.AppendChild(&html.Node{Type: html.DoctypeNode, Data: "html"})
	top := element("html")
	root.AppendChild(top)
	head := element("head")
	top.AppendChild(head)
	meta := element("meta")
	meta.Attr = []html.Attribute{{Key: "charset", Val: "utf-8"}}
	head.AppendChild(meta)
	title = strings.Join(strings.Fields(c.title), " ")
	if len(title) > maxCleanTitle {
		title = strings.ToValidUTF8(title[:maxCleanTitle], "")
	}
	if title != "" {
		t := element("title")
		t.AppendChild(&html.Node{Type: html.TextNode, Data: title})
		head.AppendChild(t)
	}
	for _, css := range c.styles {
		s := element("style")
		s.AppendChild(&html.Node{Type: html.TextNode, Data: css})
		head.AppendChild(s)
	}
	if lang := c.lang; lang != "" {
		top.Attr = []html.Attribute{{Key: "lang", Val: lang}}
	}
	body.Attr = c.bodyAttrs
	top.AppendChild(body)

	var out bytes.Buffer
	if err := html.Render(&out, root); err != nil {
		return nil, "", err
	}
	return out.Bytes(), title, nil
}

// The cleaner's bounds: a document nested deeper than this loses what is
// below (and one the parser will not follow, 512 open elements, is an error:
// its build fails and names it), and a title longer is cut.
const (
	maxCleanDepth = 256
	maxCleanTitle = 200
)

func element(name string) *html.Node {
	return &html.Node{Type: html.ElementNode, Data: name, DataAtom: atom.Lookup([]byte(name))}
}

// Elements the copy keeps, with the attributes each may have beside the
// global ones.
var cleanElements = map[string][]string{
	"div": nil, "span": nil, "p": nil, "br": nil, "hr": nil, "wbr": nil,
	"h1": nil, "h2": nil, "h3": nil, "h4": nil, "h5": nil, "h6": nil,
	"ul": nil, "ol": {"start", "reversed", "type"}, "li": {"value"},
	"dl": nil, "dt": nil, "dd": nil,
	"a":  {"href", "name"},
	"em": nil, "strong": nil, "b": nil, "i": nil, "u": nil, "s": nil, "small": nil,
	"sub": nil, "sup": nil, "mark": nil, "del": nil, "ins": nil,
	"code": nil, "pre": nil, "kbd": nil, "samp": nil, "var": nil,
	"blockquote": nil, "q": nil, "cite": nil, "abbr": nil, "dfn": nil,
	"time": {"datetime"}, "data": {"value"}, "address": nil,
	"ruby": nil, "rt": nil, "rp": nil, "bdi": nil, "bdo": nil,
	"table": nil, "caption": nil, "thead": nil, "tbody": nil, "tfoot": nil, "tr": nil,
	"th": {"colspan", "rowspan", "scope", "headers"}, "td": {"colspan", "rowspan", "headers"},
	"colgroup": {"span"}, "col": {"span"},
	"img":    {"src", "alt", "width", "height"},
	"figure": nil, "figcaption": nil,
	"section": nil, "article": nil, "header": nil, "footer": nil, "nav": nil, "aside": nil, "main": nil,
	"details": {"open"}, "summary": nil,
}

// Elements removed with everything they hold.
var cleanDropped = map[string]bool{
	"script": true, "template": true, "noscript": true, "noembed": true, "noframes": true,
	"iframe": true, "frame": true, "frameset": true, "portal": true, "fencedframe": true,
	"object": true, "embed": true, "applet": true, "param": true,
	"audio": true, "video": true, "track": true, "source": true, "picture": true, "canvas": true,
	"input": true, "button": true, "select": true, "option": true, "optgroup": true, "textarea": true,
	"datalist": true, "output": true, "progress": true, "meter": true,
	"map": true, "area": true, "link": true, "meta": true, "base": true, "dialog": true, "slot": true,
	"svg": true, "math": true,
}

var cleanGlobalAttrs = map[string]bool{"class": true, "id": true, "title": true, "lang": true, "dir": true, "role": true}

type cleaner struct {
	title     string
	lang      string
	styles    []string
	bodyAttrs []html.Attribute
}

// walk copies what of n's children is kept under to.
func (c *cleaner) walk(n, to *html.Node, depth int) {
	if depth > maxCleanDepth {
		return
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		switch ch.Type {
		case html.TextNode:
			to.AppendChild(&html.Node{Type: html.TextNode, Data: ch.Data})
		case html.ElementNode:
			c.element(ch, to, depth)
		}
	}
}

func (c *cleaner) element(n, to *html.Node, depth int) {
	if n.Namespace != "" {
		return // SVG and MathML, and what they hold
	}
	name := n.Data
	switch name {
	case "title":
		if c.title == "" {
			c.title = text(n)
		}
		return
	case "style":
		if css := text(n); checkCSS(css) == nil && !strings.Contains(strings.ToLower(css), "</style") {
			c.styles = append(c.styles, css)
		}
		return
	case "html":
		if v, ok := attr(n, "lang"); ok && c.lang == "" {
			c.lang = v
		}
		c.walk(n, to, depth+1)
		return
	case "body":
		if c.bodyAttrs == nil {
			c.bodyAttrs = c.attrs(n, nil)
		}
		c.walk(n, to, depth+1)
		return
	}
	if cleanDropped[name] {
		return
	}
	own, kept := cleanElements[name]
	if !kept {
		c.walk(n, to, depth+1) // an element the list does not know: what it holds is kept
		return
	}
	out := element(name)
	out.Attr = c.attrs(n, own)
	if name == "img" {
		if _, ok := attr(out, "src"); !ok {
			return // an image from elsewhere, or of no address
		}
	}
	to.AppendChild(out)
	c.walk(n, out, depth+1)
}

// attrs are n's attributes that are kept: the global ones, the element's own,
// a style the CSS rule passes, and aria-*.
func (c *cleaner) attrs(n *html.Node, own []string) []html.Attribute {
	var out []html.Attribute
	var elsewhere string
	titled := false
	for _, a := range n.Attr {
		if a.Namespace != "" {
			continue
		}
		key := a.Key
		switch {
		case key == "style":
			if checkCSS(a.Val) != nil {
				continue
			}
		case key == "href":
			if !contains(own, key) {
				continue
			}
			if v := stripURL(a.Val); !strings.HasPrefix(v, "#") {
				elsewhere = v
				continue
			}
		case key == "src":
			if !contains(own, key) || !localURL(a.Val) {
				continue
			}
		case cleanGlobalAttrs[key] || strings.HasPrefix(key, "aria-") || contains(own, key):
		default:
			continue
		}
		if key == "title" {
			titled = true
		}
		out = append(out, html.Attribute{Key: key, Val: a.Val})
	}
	if elsewhere != "" && !titled && navigableURL(elsewhere) {
		out = append(out, html.Attribute{Key: "title", Val: elsewhere})
	}
	return out
}

// text is the text an element holds directly.
func text(n *html.Node) string {
	var b strings.Builder
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if ch.Type == html.TextNode {
			b.WriteString(ch.Data)
		}
	}
	return b.String()
}
