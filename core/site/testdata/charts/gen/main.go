package main

import (
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"

	"github.com/yongjohnlee80/golib/gui"
	"github.com/yongjohnlee80/golib/gui/vegalite"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "subset" {
		b, _ := json.MarshalIndent(vegalite.Subset().Marks, "", " ")
		fmt.Println(string(b))
		return
	}
	m, release := gui.AcquireMeasurer(1)
	defer release()
	files, _ := filepath.Glob("specs/*.json")
	os.MkdirAll("out", 0o755) // then: cp out/*.svg ..
	for _, f := range files {
		spec, _ := os.ReadFile(f)
		laid, err := vegalite.Lay(context.Background(), string(spec), 640, vegalite.Theme{
			Background: color.NRGBA{255, 255, 255, 255}, Text: color.NRGBA{20, 20, 20, 255},
			Axis: color.NRGBA{100, 100, 100, 255}, Grid: color.NRGBA{220, 220, 220, 255},
		}, m)
		if err != nil {
			fmt.Println(f, "ERR", err)
			continue
		}
		c := gui.NewSVGCanvas(laid.Size(), nil)
		laid.Paint(c)
		name := strings.TrimSuffix(filepath.Base(f), ".json") + ".svg"
		os.WriteFile(filepath.Join("out", name), c.Bytes(), 0o644)
		fmt.Println(f, "ok", len(c.Bytes()))
	}
}
