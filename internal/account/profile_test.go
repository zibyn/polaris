package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type profileBody struct {
	Nickname string `json:"nickname"`
	Picture  string `json:"picture"`
}

func pngOf(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// send sends a raw body with a bearer token and decodes a 2xx JSON answer
// into out; it returns the status.
func (e *env) send(method, token, path, contentType string, body []byte, out any) int {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.issuer+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: %v %s", method, path, err, raw)
		}
	}
	return resp.StatusCode
}

func (e *env) blobs() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM blobs").Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// fetch GETs a public URL: its status and body.
func fetch(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // the test server
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// The account center sets the nickname, uploads and removes the avatar;
// me shows both.
func TestAccountCenterProfile(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", time.Hour) // no reauthentication needed

	var p profileBody
	if c := e.call("PATCH", tok, "/v1/account/profile", map[string]string{"nickname": "  爱丽丝 "}, &p); c != 200 || p.Nickname != "爱丽丝" {
		t.Fatalf("set nickname: %d %+v", c, p)
	}
	for _, bad := range []string{strings.Repeat("长", 33), "a\u0007b"} {
		if c := e.call("PATCH", tok, "/v1/account/profile", map[string]string{"nickname": bad}, nil); c != 400 {
			t.Errorf("nickname %q: %d", bad, c)
		}
	}

	if c := e.send("PUT", tok, "/v1/account/avatar", "image/png", pngOf(t, 600, 400), &p); c != 200 || p.Picture == "" {
		t.Fatalf("upload: %d %+v", c, p)
	}
	first := p.Picture
	if c, _ := fetch(t, first); c != 200 {
		t.Errorf("avatar: %d", c)
	}
	if c := e.send("PUT", tok, "/v1/account/avatar", "image/jpeg", []byte("not an image at all"), nil); c != 400 {
		t.Errorf("not an image: %d", c)
	}
	if c := e.send("PUT", tok, "/v1/account/avatar", "image/png", make([]byte, 5<<20+1), nil); c != 413 {
		t.Errorf("over 5 MB: %d", c)
	}

	// A second upload is a new URL; the old one is gone.
	if c := e.send("PUT", tok, "/v1/account/avatar", "image/png", pngOf(t, 50, 50), &p); c != 200 || p.Picture == first {
		t.Fatalf("second upload: %d %+v", c, p)
	}
	if c, _ := fetch(t, first); c != 404 {
		t.Errorf("old avatar: %d", c)
	}
	if n := e.blobs(); n != 1 {
		t.Errorf("%d blobs", n)
	}

	var got profileBody
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 || got != p {
		t.Errorf("me: %d %+v, want %+v", c, got, p)
	}

	p = profileBody{} // absent fields leave what was decoded before
	if c := e.call("DELETE", tok, "/v1/account/avatar", nil, &p); c != 200 || p.Picture != "" || p.Nickname != "爱丽丝" {
		t.Errorf("remove avatar: %d %+v", c, p)
	}
	if n := e.blobs(); n != 0 {
		t.Errorf("%d blobs after removal", n)
	}
	p = profileBody{}
	if c := e.call("PATCH", tok, "/v1/account/profile", map[string]string{"nickname": " "}, &p); c != 200 || p.Nickname != "" {
		t.Errorf("clear nickname: %d %+v", c, p)
	}
}

// Deleting the account takes the avatar with it.
func TestDeleteAccountDeletesTheAvatar(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	var p profileBody
	if c := e.send("PUT", tok, "/v1/account/avatar", "image/png", pngOf(t, 10, 10), &p); c != 200 {
		t.Fatalf("upload: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/me", nil, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if n := e.blobs(); n != 0 {
		t.Errorf("%d blobs left", n)
	}
	if c, _ := fetch(t, p.Picture); c != 404 {
		t.Errorf("avatar after deletion: %d", c)
	}
}

// An App's own access token changes its User's 用户资料 on the direct auth
// API, and only theirs.
func TestDirectAPIProfile(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "phone:+8613900139000")
	tok := e.signIn("ALICE", time.Hour)
	claims, _ := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	var c map[string]any
	_ = claims.UnsafeClaimsWithoutVerification(&c)
	app := e.token("ALICE", map[string]any{"sid": c["sid"], "aud": "https://track.example", "client_id": "app"})

	var p profileBody
	if code := e.call("PATCH", app, "/v1/auth/profile", map[string]string{"nickname": "Alice"}, &p); code != 200 || p.Nickname != "Alice" {
		t.Fatalf("set nickname: %d %+v", code, p)
	}
	if code := e.call("PATCH", app, "/v1/auth/profile", map[string]string{"nickname": strings.Repeat("x", 33)}, nil); code != 400 {
		t.Errorf("long nickname: %d", code)
	}
	for _, bad := range []string{"", "garbage", e.token("BOB", nil)} {
		if code := e.call("PATCH", bad, "/v1/auth/profile", map[string]string{"nickname": "Mallory"}, nil); code != 401 {
			t.Errorf("token %.10q: %d", bad, code)
		}
	}
	if code := e.send("PUT", app, "/v1/auth/profile/avatar", "image/png", pngOf(t, 30, 30), &p); code != 200 || p.Picture == "" {
		t.Fatalf("upload: %d %+v", code, p)
	}
	if code := e.send("PUT", app, "/v1/auth/profile/avatar", "image/png", []byte("<svg/>"), nil); code != 400 {
		t.Errorf("not an image: %d", code)
	}
	p = profileBody{}
	if code := e.call("DELETE", app, "/v1/auth/profile/avatar", nil, &p); code != 200 || p.Picture != "" {
		t.Errorf("remove: %d %+v", code, p)
	}
	var bob profileBody
	bobTok := e.signIn("BOB", 0)
	if code := e.call("GET", bobTok, "/v1/account/me", nil, &bob); code != 200 || bob.Nickname != "" {
		t.Errorf("Bob changed: %+v", bob)
	}
}
