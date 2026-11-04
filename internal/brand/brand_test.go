package brand

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"testing"
)

func TestCheckColor(t *testing.T) {
	for in, want := range map[string]error{
		"#7048E8":                    nil,         // 星云, 5.4:1
		"#000000":                    nil,         // as dark as it gets
		"#ffff00":                    ErrContrast, // yellow under white text
		"#767676":                    nil,         // just over 4.5:1
		"#777777":                    ErrContrast, // just under
		"7048e8":                     ErrColor,
		"#7048e":                     ErrColor,
		"red":                        ErrColor,
		"#7048e8;}body{display:none": ErrColor,
	} {
		if _, err := CheckColor(in); err != want {
			t.Errorf("CheckColor(%q) = %v, want %v", in, err, want)
		}
	}
	if c, _ := CheckColor("#7048E8"); c != "#7048e8" {
		t.Errorf("stored as %q", c)
	}
}

// Every shade derived from a colour CheckColor takes keeps the pages
// readable: ink on soft at 4.5:1, and hover darker than the colour.
func TestPalette(t *testing.T) {
	shade := regexp.MustCompile(`--primary(-\w+)?: (#[0-9a-f]{6});`)
	for _, c := range []string{"#7048e8", "#000000", "#767676", "#0a66c2", "#d00000", "#007a33"} {
		css := string(Palette(c))
		m := map[string]rgb{}
		for _, s := range shade.FindAllStringSubmatch(css, -1) {
			m[s[1]] = parse(s[2])
		}
		if len(m) != 4 || m[""] != parse(c) {
			t.Fatalf("%s: %s", c, css)
		}
		if r := contrast(m["-ink"], m["-soft"]); r < 4.5 {
			t.Errorf("%s: ink on soft %.2f in %s", c, r, css)
		}
		if m["-hover"].luminance() > m[""].luminance() {
			t.Errorf("%s: hover lighter in %s", c, css)
		}
	}
}

func TestLogoType(t *testing.T) {
	png, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
	for name, c := range map[string]struct {
		b    []byte
		want string
		err  error
	}{
		"png":             {png, "image/png", nil},
		"webp":            {[]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), "image/webp", nil},
		"svg":             {[]byte(`<?xml version="1.0"?><!-- logo --><svg xmlns="http://www.w3.org/2000/svg"/>`), "image/svg+xml", nil},
		"svg, no prolog":  {[]byte(`<svg viewBox="0 0 1 1"><script>alert(1)</script></svg>`), "image/svg+xml", nil},
		"html":            {[]byte(`<html><svg/></html>`), "", ErrLogoType},
		"jpeg":            {[]byte("\xff\xd8\xff\xe0\x00\x10JFIF"), "", ErrLogoType},
		"text":            {[]byte("hello"), "", ErrLogoType},
		"over 1 MB":       {append(bytes.Clone(png), make([]byte, MaxLogoBytes)...), "", ErrLogoTooBig},
		"other namespace": {[]byte(`<svg xmlns="urn:x"/>`), "", ErrLogoType},
	} {
		got, err := LogoType(c.b)
		if got != c.want || err != c.err {
			t.Errorf("%s: %q %v, want %q %v", name, got, err, c.want, c.err)
		}
	}
}
