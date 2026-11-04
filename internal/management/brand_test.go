package management_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/management"
)

var pngLogo, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")

type brandBody struct {
	Name  string `json:"name,omitempty"`
	Logo  string `json:"logo,omitempty"`
	Color string `json:"color,omitempty"`
}

// upload PUTs b raw to path and returns the status and the Logo reference.
func (e *env) upload(token, path string, b []byte) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest("PUT", e.issuer+management.Prefix+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	var out struct{ Logo string }
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out.Logo
}

func (e *env) logoBlobs() []string {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT key FROM blobs WHERE key LIKE 'brand/%' ORDER BY key")
	if err != nil {
		e.t.Fatal(err)
	}
	var keys []string
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		keys = append(keys, strings.TrimPrefix(k, "brand/"))
	}
	return keys
}

// The instance's 品牌: a Logo judged by its bytes, a colour that
// must read under white text, every change audited, and a replaced Logo's
// blob gone.
func TestInstanceBrand(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	type withBrand struct {
		settings
		Brand *brandBody `json:"brand,omitempty"`
	}
	var policy withBrand
	if code := e.get(owner, "/settings", &policy); code != 200 || policy.Brand != nil {
		t.Fatalf("no brand at first: %d %+v", code, policy.Brand)
	}

	for name, b := range map[string][]byte{
		"jpeg":      []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
		"html":      []byte("<html><script>alert(1)</script></html>"),
		"over 1 MB": append(bytes.Clone(pngLogo), make([]byte, 1<<20)...),
	} {
		if code, _ := e.upload(owner, "/settings/brand/logo", b); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}
	code, first := e.upload(owner, "/settings/brand/logo", pngLogo)
	if code != 200 || first == "" {
		t.Fatalf("upload: %d %q", code, first)
	}
	_, second := e.upload(owner, "/settings/brand/logo", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
	if got := e.logoBlobs(); len(got) != 1 || got[0] != second {
		t.Errorf("after replacing: blobs %v, want only %s", got, second)
	}

	policy = withBrand{}
	e.get(owner, "/settings", &policy)
	for _, bad := range []string{"#ffff00", "7048e8", "#7048e8;}", "red"} {
		policy.Brand = &brandBody{Name: "Acme", Logo: second, Color: bad}
		if code := e.call("PUT", owner, "/settings", policy, nil); code != 422 {
			t.Errorf("colour %q: %d, want 422", bad, code)
		}
	}
	policy.Brand = &brandBody{Name: "Acme", Logo: "someone-elses", Color: "#0A66C2"}
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 422 {
		t.Errorf("a Logo not uploaded here: %d, want 422", code)
	}
	policy.Brand.Logo = second
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("save: %d", code)
	}
	var got withBrand
	e.get(owner, "/settings", &got)
	if got.Brand == nil || *got.Brand != (brandBody{Name: "Acme", Logo: second, Color: "#0a66c2"}) {
		t.Errorf("read back: %+v", got.Brand)
	}

	// Leaving the Logo out removes it, and its blob.
	policy.Brand.Logo = ""
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("drop the Logo: %d", code)
	}
	if got := e.logoBlobs(); len(got) != 0 {
		t.Errorf("blobs left: %v", got)
	}
	if n := len(e.events("event=settings.updated")); n < 4 {
		t.Errorf("settings.updated events: %d, want one per change", n)
	}
}

// An Application overrides the instance's 品牌 item by item; leaving its
// brand out follows the instance again, and deleting it takes its Logo.
// The built-in and M2M Applications have none.
func TestApplicationBrand(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	type app struct {
		ClientID string
		Brand    *brandBody
	}
	settings := map[string]any{
		"name": "商城", "redirectUris": []string{"https://shop.example/cb"}, "postLogoutRedirectUris": []string{},
		"refreshTokens": true, "appleAppIds": []string{}, "androidApps": []any{},
		"brand": brandBody{Color: "#d00000"},
	}
	var created struct{ Application app }
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "public", "settings": settings}, &created); code != 200 ||
		created.Application.Brand == nil || created.Application.Brand.Color != "#d00000" {
		t.Fatalf("create: %d %+v", code, created.Application.Brand)
	}
	path := "/applications/" + created.Application.ClientID
	code, logo := e.upload(owner, path+"/brand/logo", pngLogo)
	if code != 200 {
		t.Fatalf("upload: %d", code)
	}
	var got app
	e.get(owner, path, &got)
	if got.Brand == nil || got.Brand.Logo != logo || got.Brand.Color != "#d00000" {
		t.Errorf("after upload: %+v", got.Brand)
	}
	if n := len(e.events("event=application.updated")); n != 1 {
		t.Errorf("application.updated after the upload: %d", n)
	}

	// Leaving the brand out follows the instance, the Logo's blob deleted.
	delete(settings, "brand")
	if code := e.call("PUT", owner, path, settings, nil); code != 204 {
		t.Fatalf("follow: %d", code)
	}
	got = app{}
	e.get(owner, path, &got)
	if got.Brand != nil || len(e.logoBlobs()) != 0 {
		t.Errorf("following: %+v, blobs %v", got.Brand, e.logoBlobs())
	}

	e.upload(owner, path+"/brand/logo", pngLogo)
	if code := e.call("DELETE", owner, path, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if got := e.logoBlobs(); len(got) != 0 {
		t.Errorf("deleted Application's Logo left: %v", got)
	}

	m2m := m2mSettings(identity.ManagementAPI)
	m2m["brand"] = brandBody{Name: "x"}
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "m2m", "settings": m2m}, nil); code != 422 {
		t.Errorf("M2M with a brand: %d, want 422", code)
	}
	m2mID := e.m2mApp(identity.ManagementAPI)
	if code, _ := e.upload(owner, "/applications/"+m2mID+"/brand/logo", pngLogo); code != 422 {
		t.Errorf("M2M Logo: %d, want 422", code)
	}
	settings["brand"] = brandBody{Name: "x"}
	for _, builtin := range []string{identity.ConsoleClientID, identity.AccountClientID} {
		if code := e.call("PUT", owner, "/applications/"+builtin, settings, nil); code != 422 {
			t.Errorf("%s with a brand: %d, want 422", builtin, code)
		}
		if code, _ := e.upload(owner, "/applications/"+builtin+"/brand/logo", pngLogo); code != 422 {
			t.Errorf("%s Logo: %d, want 422", builtin, code)
		}
	}
}
