package profile_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/profile"
)

func TestCheckNickname(t *testing.T) {
	for in, want := range map[string]string{
		"  小明  ":                "小明",
		"   ":                   "", // clears it
		"":                      "",
		strings.Repeat("字", 32): strings.Repeat("字", 32),
	} {
		if got, err := profile.CheckNickname(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{strings.Repeat("a", 33), "a\nb", "a\x00b", "tab\there", "del\x7f"} {
		if _, err := profile.CheckNickname(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// pngOf is a solid PNG of w×h.
func pngOf(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{200, 10, 10, 255}}, image.Point{}, draw.Src)
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// jpegWithGPS is a JPEG carrying an EXIF segment with a GPS tag in it.
func jpegWithGPS(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, 800, 600)), nil); err != nil {
		t.Fatal(err)
	}
	exif := append([]byte("Exif\x00\x00"), []byte("GPSLatitude 31.2304N")...)
	app1 := append([]byte{0xFF, 0xE1, byte((len(exif) + 2) >> 8), byte(len(exif) + 2)}, exif...)
	raw := b.Bytes()
	return append(append(append([]byte{}, raw[:2]...), app1...), raw[2:]...)
}

// webpFixture is a lossless 40×30 WebP.
const webpFixture = "UklGRh4AAABXRUJQVlA4TBEAAAAvJ0AHAAdQ5CrUo/+BiOh/AAA="

// WebP is a tiny lossless WebP.
func WebP(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(webpFixture)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkAvatar asserts jpg is a 512×512 JPEG with no EXIF.
func checkAvatar(t *testing.T, name string, jpg []byte) {
	t.Helper()
	c, format, err := image.DecodeConfig(bytes.NewReader(jpg))
	if err != nil || format != "jpeg" || c.Width != 512 || c.Height != 512 {
		t.Errorf("%s: %s %dx%d %v", name, format, c.Width, c.Height, err)
	}
	if bytes.Contains(jpg, []byte("Exif")) || bytes.Contains(jpg, []byte("GPS")) {
		t.Errorf("%s: metadata kept", name)
	}
}

func TestAvatarIsA512SquareJPEG(t *testing.T) {
	for name, in := range map[string][]byte{
		"png":       pngOf(t, 1000, 300),
		"jpeg+exif": jpegWithGPS(t),
		"webp":      WebP(t),
	} {
		out, err := profile.Avatar(bytes.NewReader(in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		checkAvatar(t, name, out)
	}
}

func TestAvatarRefusesWhatIsNotAnImage(t *testing.T) {
	big := append(pngOf(t, 10, 10), make([]byte, profile.MaxAvatarBytes)...)
	if _, err := profile.Avatar(bytes.NewReader(big)); !errors.Is(err, profile.ErrImageTooLarge) {
		t.Errorf("over 5 MB: %v", err)
	}
	for name, in := range map[string][]byte{
		"text":      []byte("just text, named photo.jpg"),
		"gif":       []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00;"),
		"truncated": pngOf(t, 10, 10)[:40],
	} {
		if _, err := profile.Avatar(bytes.NewReader(in)); !errors.Is(err, profile.ErrNotImage) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
