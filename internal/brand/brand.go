// Package brand is the 品牌 hosted pages show (ADR 0028): checking a primary
// colour and the four shades the pages derive from it, checking a Logo, and
// serving Logos.
package brand

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/zibyn/polaris/internal/blob"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

const (
	ErrColor       identity.Invalid = "主色须为 #rrggbb"
	ErrContrast    identity.Invalid = "请换深一些的主色:白字放在它上面,对比度要达到 4.5:1(WCAG AA)"
	ErrLogoType    identity.Invalid = "Logo 须为 PNG、WebP 或 SVG 图片"
	ErrLogoTooBig  identity.Invalid = "Logo 不能超过 1 MB"
	ErrLogoUnknown identity.Invalid = "Logo 须先上传:只能原样带回已上传的 Logo,或留空去掉它"
)

// MaxLogoBytes is the largest Logo taken.
const MaxLogoBytes = 1 << 20

// KeyPrefix starts the blob key of every Logo.
const KeyPrefix = "brand/"

// LogoPath is where the Logo of key is served.
func LogoPath(key string) string { return "/brand-logos/" + key }

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// CheckColor is color as stored, lower case, or why it is refused: not
// #rrggbb, or white text on it (and it on white) under WCAG AA's 4.5:1.
func CheckColor(color string) (string, error) {
	c := strings.ToLower(color)
	if !hexColor.MatchString(c) {
		return "", ErrColor
	}
	if contrast(parse(c), rgb{1, 1, 1}) < 4.5 {
		return "", ErrContrast
	}
	return c, nil
}

// rgb is a colour with channels from 0 to 1.
type rgb struct{ r, g, b float64 }

func parse(hex string) rgb {
	n, _ := strconv.ParseUint(hex[1:], 16, 32)
	return rgb{float64(n>>16&0xff) / 255, float64(n>>8&0xff) / 255, float64(n&0xff) / 255}
}

func (c rgb) String() string {
	ch := func(v float64) int { return int(math.Round(math.Max(0, math.Min(1, v)) * 255)) }
	return fmt.Sprintf("#%02x%02x%02x", ch(c.r), ch(c.g), ch(c.b))
}

// mix is c moved toward to by w (0 to 1).
func (c rgb) mix(to rgb, w float64) rgb {
	return rgb{c.r + (to.r-c.r)*w, c.g + (to.g-c.g)*w, c.b + (to.b-c.b)*w}
}

// luminance is WCAG 2's relative luminance.
func (c rgb) luminance() float64 {
	lin := func(v float64) float64 {
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b)
}

func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}

// Palette is the CSS that overrides the pages' four primary shades with
// those of color, a colour CheckColor took: hover is darker, soft a tint
// for the brand panel, and ink, for text on soft, darkened until it reads
// at 4.5:1 there.
func Palette(color string) template.CSS {
	p := parse(color)
	black, white := rgb{}, rgb{1, 1, 1}
	soft := p.mix(white, 0.92)
	ink := p
	for i := 0; i < 20 && contrast(ink, soft) < 4.5; i++ {
		ink = ink.mix(black, 0.05)
	}
	//nolint:gosec // every value is #rrggbb, made here
	return template.CSS(fmt.Sprintf("--primary: %s; --primary-hover: %s; --primary-soft: %s; --primary-ink: %s;",
		p, p.mix(black, 0.12), soft, ink))
}

// LogoType is the content type of a Logo, sniffed from its bytes, or why
// it is refused. It is not decoded or re-encoded: an SVG keeps its scripts,
// which the sandbox the Logo is served under (Serve) keeps from running.
func LogoType(b []byte) (string, error) {
	if len(b) > MaxLogoBytes {
		return "", ErrLogoTooBig
	}
	switch t := http.DetectContentType(b); t {
	case "image/png", "image/webp":
		return t, nil
	}
	if isSVG(b) {
		return "image/svg+xml", nil
	}
	return "", ErrLogoType
}

// isSVG reports whether b is XML whose root element is svg.
func isSVG(b []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return false
		}
		if el, ok := tok.(xml.StartElement); ok {
			return el.Name.Local == "svg" && (el.Name.Space == "" || el.Name.Space == "http://www.w3.org/2000/svg")
		}
	}
}

// Serve adds the public Logo route: what is written under a key never
// changes, and the sandbox keeps an SVG's scripts from running even when
// it is opened on its own.
func Serve(mux *http.ServeMux, q *sqlc.Queries) {
	mux.HandleFunc("GET /brand-logos/{key}", func(w http.ResponseWriter, r *http.Request) {
		b, contentType, err := blob.NewPG(q).Get(r.Context(), KeyPrefix+r.PathValue("key"))
		if errors.Is(err, blob.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Security-Policy", "sandbox")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(b)
	})
}
