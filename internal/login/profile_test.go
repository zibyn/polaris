package login_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/blob"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/profile"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 64, 64))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The profile scope brings nickname and picture, in the ID token and from
// userinfo, and only the ones the User has.
func TestProfileClaims(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"
	login := func(scope string) (idToken, userinfo map[string]any) {
		e.newBrowser()
		_, page := e.authorize("&scope=" + scope)
		resp, _ := e.codeLogin(page, phone, phone)
		tok := e.exchange(clientID, callback, e.code(resp))
		return e.claims(tok.IDToken), e.userinfo(tok.AccessToken)
	}

	id, info := login("openid+profile")
	sub := id["sub"].(string)
	for name, claims := range map[string]map[string]any{"id token": id, "userinfo": info} {
		if _, ok := claims["nickname"]; ok {
			t.Errorf("%s: nickname without one: %v", name, claims)
		}
		if _, ok := claims["picture"]; ok {
			t.Errorf("%s: picture without one: %v", name, claims)
		}
	}

	ctx := context.Background()
	profiles := profile.New(e.pool, e.issuer)
	nickname, name, city := " 小明 ", "王小明", "上海"
	if err := profiles.Update(ctx, sub, profile.Patch{Nickname: &nickname, Name: &name, Address: &profile.Address{Locality: city}}, audit.User(sub)); err != nil {
		t.Fatal(err)
	}
	if err := profiles.SetAvatar(ctx, sub, bytes.NewReader(pngBytes(t)), audit.User(sub)); err != nil {
		t.Fatal(err)
	}
	id, info = login("openid+profile")
	for what, claims := range map[string]map[string]any{"id token": id, "userinfo": info} {
		pic, _ := claims["picture"].(string)
		if claims["nickname"] != "小明" || !strings.HasPrefix(pic, e.issuer+"/avatars/") || claims["name"] != "王小明" ||
			claims["updated_at"] == nil || claims["address"] != nil || claims["given_name"] != nil {
			t.Errorf("%s: %v", what, claims)
		}
	}
	// address is its own scope.
	addrID, addrInfo := login("openid+address")
	for what, claims := range map[string]map[string]any{"id token": addrID, "userinfo": addrInfo} {
		if a, _ := claims["address"].(map[string]any); a["locality"] != "上海" || len(a) != 1 || claims["name"] != nil {
			t.Errorf("%s: %v", what, claims)
		}
	}
	// The picture is served to anyone, as a JPEG cached for good.
	resp, err := e.client.Get(id["picture"].(string)) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if _, format, err := image.DecodeConfig(bytes.NewReader(body)); resp.StatusCode != 200 || format != "jpeg" || err != nil ||
		resp.Header.Get("Content-Type") != "image/jpeg" ||
		resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("avatar: %d %s %v %v", resp.StatusCode, format, err, resp.Header)
	}

	id, info = login("openid")
	if id["nickname"] != nil || id["picture"] != nil || info["nickname"] != nil || info["picture"] != nil {
		t.Errorf("without profile: %v %v", id, info)
	}
}

// The username Identifier is preferred_username, under the profile scope only.
func TestPreferredUsername(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	login := func(scope string) (idToken, userinfo map[string]any) {
		e.newBrowser()
		_, page := e.authorize("&scope=" + scope)
		resp, _ := e.submit(page, "owner", "password1")
		tok := e.exchange(clientID, callback, e.code(resp))
		return e.claims(tok.IDToken), e.userinfo(tok.AccessToken)
	}
	id, info := login("openid+profile")
	if id["preferred_username"] != "owner" || info["preferred_username"] != "owner" {
		t.Errorf("with profile: %v %v", id, info)
	}
	id, info = login("openid")
	if id["preferred_username"] != nil || info["preferred_username"] != nil {
		t.Errorf("without profile: %v %v", id, info)
	}
}

func TestDiscoveryListsProfile(t *testing.T) {
	e := start(t)
	_, body := e.do("GET", "/.well-known/openid-configuration", nil)
	var meta struct {
		Scopes []string `json:"scopes_supported"`
		Claims []string `json:"claims_supported"`
	}
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(meta.Scopes, "profile") || !slices.Contains(meta.Claims, "nickname") || !slices.Contains(meta.Claims, "picture") ||
		!slices.Contains(meta.Claims, "preferred_username") || !slices.Contains(meta.Scopes, "address") ||
		!slices.Contains(meta.Claims, "address") || !slices.Contains(meta.Claims, "updated_at") {
		t.Errorf("discovery: %+v", meta)
	}
}

// /avatars/ serves avatars only, not whatever else the blob store holds.
func TestUnknownAvatarIsNotFound(t *testing.T) {
	e := start(t)
	if err := blob.NewPG(sqlc.New(e.pool)).Put(context.Background(), "other", []byte("secret"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"NOSUCHKEY", "other", "..%2Fother"} {
		if resp, _ := e.do("GET", "/avatars/"+key, nil); resp.StatusCode != 404 {
			t.Errorf("%s: %d", key, resp.StatusCode)
		}
	}
}
