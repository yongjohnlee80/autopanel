# Chart fixtures

What golib's chart writer (`gui/vegalite` drawing on `gui.SVGCanvas`) emits, as AutoDoc's export
draws a Vega-Lite chart. The site's output check (`check_page.go`, the SVG allowlist) must pass
every one of them inside a page.

Made with golib gui v0.3.10, one spec per mark type it draws (area, bar, circle, line, point,
rule) and golib's own test specs. When the version AutoDoc's `Fragment` pins changes, make them
again and run the tests:

```sh
cd gen && go mod tidy && go run -tags gui . && cp out/*.svg ..
```

The generator is its own module under `testdata`, so AutoPanel does not depend on golib's GUI.
