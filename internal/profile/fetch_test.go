package profile

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A Provider's avatar is fetched over https only, and re-encoded.
func TestFetchAvatar(t *testing.T) {
	var img bytes.Buffer
	_ = png.Encode(&img, image.NewRGBA(image.Rect(0, 0, 40, 20)))
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(img.Bytes()) }))
	defer ts.Close()
	old := fetchClient
	fetchClient = ts.Client()
	defer func() { fetchClient = old }()

	jpg, err := FetchAvatar(context.Background(), ts.URL+"/a.png")
	if err != nil || http.DetectContentType(jpg) != "image/jpeg" {
		t.Errorf("https: %v, %s", err, http.DetectContentType(jpg))
	}
	if _, err := FetchAvatar(context.Background(), "http://example.com/a.png"); err != ErrNotImage {
		t.Errorf("http: %v", err)
	}
}
