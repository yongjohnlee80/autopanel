package site

import (
	"errors"
	"strings"
	"testing"
)

// TestAResourceIsWhatItsNameSays: a file's kind is decided from its name and
// its first bytes together, so a renamed file is refused and nothing is
// served as a type its sender chose.
func TestAResourceIsWhatItsNameSays(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n....")
	jpg := []byte{0xff, 0xd8, 0xff, 0xe0, 1, 2}
	gif := []byte("GIF89a....")
	webp := []byte("RIFF\x00\x00\x00\x00WEBPVP8 ")
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	for name, tc := range map[string]struct {
		data []byte
		mime string
		err  error
	}{
		"flow.png":           {png, "image/png", nil},
		"a/Photo.JPG":        {jpg, "image/jpeg", nil},
		"photo.jpeg":         {jpg, "image/jpeg", nil},
		"anim.gif":           {gif, "image/gif", nil},
		"shot.webp":          {webp, "image/webp", nil},
		"drain-flow.mmd":     {[]byte("flowchart LR\n a --> b\n"), "text/plain; charset=utf-8", nil},
		"latency.chart.json": {[]byte(`{"mark":"bar"}`), "text/plain; charset=utf-8", nil},
		"queue.csv":          {[]byte("a,b\n1,2\n"), "text/plain; charset=utf-8", nil},
		"empty.csv":          {nil, "text/plain; charset=utf-8", nil},
		"renamed.png":        {jpg, "", ErrResourceType},
		"script.png":         {svg, "", ErrResourceType},
		"page.png":           {[]byte("<html><script>1</script></html>"), "", ErrResourceType},
		"logo.svg":           {svg, "", ErrResourceType},
		"sim.html":           {[]byte("<html></html>"), "", ErrResourceType},
		"notes.md":           {[]byte("# x"), "", ErrResourceType},
		"backfill.sql":       {[]byte("select 1"), "", ErrResourceType},
		"data.json":          {[]byte("{}"), "", ErrResourceType}, // only a chart's .chart.json
		"clip.mp4":           {[]byte("\x00\x00\x00\x18ftypmp42"), "", ErrResourceType},
		"noext":              {png, "", ErrResourceType},
		"binary.csv":         {[]byte("a,b\x00c"), "", ErrResourceType},
		"notutf8.mmd":        {[]byte("flow\xff"), "", ErrResourceType},
		"huge.png":           {append(append([]byte{}, png...), make([]byte, MaxImageBytes)...), "", ErrResourceSize},
		"huge.csv":           {[]byte(strings.Repeat("a", MaxTextBytes+1)), "", ErrResourceSize},
	} {
		mime, err := ResourceType(name, tc.data)
		if mime != tc.mime || !errors.Is(err, tc.err) {
			t.Errorf("%s: %q, %v; want %q, %v", name, mime, err, tc.mime, tc.err)
		}
	}
	if (Resource{MIME: "image/png"}).Attachment() || !(Resource{MIME: "text/plain; charset=utf-8"}).Attachment() {
		t.Error("an image is shown, and everything else is handed over to save")
	}
}
