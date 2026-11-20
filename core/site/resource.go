package site

import (
	"bytes"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

// Resource is one file of a document: an image it shows, a diagram or a
// chart it embeds, a table.
type Resource struct {
	ID     int64
	Doc    int64
	Name   string // the author's relative path, as ResourceName took it
	MIME   string // decided from the file's content and its name together, never from what the sender said
	Size   int64
	SHA256 string
}

// The most a resource may hold.
const (
	MaxImageBytes = 1468006 // 1.4 MiB
	MaxTextBytes  = 512 << 10
)

var (
	ErrResourceType  = errors.New("site: a resource is a PNG, JPEG, WebP or GIF image, a Mermaid diagram (.mmd), a Vega-Lite chart (.chart.json) or a table (.csv); its content must be what its name says")
	ErrResourceSize  = errors.New("site: a resource is too large: an image holds at most 1.4 MiB, a diagram, chart or table 512 KiB")
	ErrNoResource    = errors.New("site: the document has no such resource")
	ErrResourceTaken = errors.New("site: the document has a resource whose name differs from this one only by case")
)

// A resource's kind, by what it is served as.
const (
	mimePNG  = "image/png"
	mimeJPEG = "image/jpeg"
	mimeWebP = "image/webp"
	mimeGIF  = "image/gif"
	// Diagrams, charts and tables are a build's input. Asked for directly
	// they are plain text to be saved, never something a browser acts on.
	mimeText = "text/plain; charset=utf-8"
)

// ResourceType decides what a resource is from its name and its content
// together: the name says what the author means, the first bytes say what it
// is, and they must agree. So a renamed file is refused, and a file is never
// served as a type its sender chose. SVG is not an image here: it can carry
// script.
func ResourceType(name string, data []byte) (mime string, err error) {
	ext := strings.ToLower(path.Ext(name))
	lower := strings.ToLower(name)
	switch {
	case ext == ".png":
		mime = mimePNG
	case ext == ".jpg" || ext == ".jpeg":
		mime = mimeJPEG
	case ext == ".webp":
		mime = mimeWebP
	case ext == ".gif":
		mime = mimeGIF
	case ext == ".mmd" || ext == ".csv" || strings.HasSuffix(lower, ".chart.json"):
		mime = mimeText
	default:
		return "", ErrResourceType
	}
	if mime == mimeText {
		if len(data) > MaxTextBytes {
			return "", ErrResourceSize
		}
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return "", ErrResourceType
		}
		return mime, nil
	}
	if len(data) > MaxImageBytes {
		return "", ErrResourceSize
	}
	if sniffImage(data) != mime {
		return "", ErrResourceType
	}
	return mime, nil
}

// sniffImage names the image format data starts as, or "".
func sniffImage(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return mimePNG
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		return mimeJPEG
	case bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")):
		return mimeGIF
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return mimeWebP
	}
	return ""
}

// Attachment reports whether a resource asked for directly is handed over as
// a file to save rather than shown: everything that is not an image.
func (r Resource) Attachment() bool { return !strings.HasPrefix(r.MIME, "image/") }
