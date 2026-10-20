package management_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	_ "github.com/zibyn/polaris/internal/channel/aliyun"
	_ "github.com/zibyn/polaris/internal/channel/smtp"
	_ "github.com/zibyn/polaris/internal/channel/webhook"
)

type channels struct {
	Plugins []struct {
		Key    string
		Kinds  []string
		Fields []struct {
			Key    string
			Secret bool
		}
	}
	Channels []struct {
		Kind, Plugin string
		Config       map[string]string
		Secrets      map[string]time.Time
	}
}

// receiver is a webhook endpoint that checks the signature against secret
// and hands over each code it gets.
func receiver(t *testing.T, secret string) (string, chan string) {
	t.Helper()
	codes := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, v1, _ := strings.Cut(r.Header.Get("X-Polaris-Signature"), ",v1=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strings.TrimPrefix(ts, "t=") + "."))
		mac.Write(body)
		if v1 != hex.EncodeToString(mac.Sum(nil)) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var p struct{ Code string }
		_ = json.Unmarshal(body, &p)
		codes <- p.Code
	}))
	t.Cleanup(ts.Close)
	return ts.URL, codes
}

func TestAdminConfiguresChannelAndSendsTestCode(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)
	url, codes := receiver(t, "s3cret")

	var got channels
	if code := e.get(ro, "/channels", &got); code != 200 || len(got.Channels) != 0 {
		t.Fatalf("channels: %d %+v", code, got)
	}
	var keys []string
	for _, p := range got.Plugins {
		keys = append(keys, p.Key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"aliyun-pnvs-sms", "smtp", "webhook"}) {
		t.Errorf("plugins: %v", keys)
	}

	put := map[string]any{"plugin": "webhook", "config": map[string]string{"url": url, "secret": "s3cret"}}
	if code := e.call("PUT", ro, "/channels/phone", put, nil); code != 403 {
		t.Errorf("readonly PUT: %d, want 403", code)
	}
	if code := e.call("PUT", owner, "/channels/phone", put, nil); code != 204 {
		t.Fatalf("PUT: %d", code)
	}

	// Secret fields are write-only: the API says when, never what.
	var raw json.RawMessage
	e.get(ro, "/channels", &raw)
	if strings.Contains(string(raw), "s3cret") {
		t.Errorf("secret read back: %s", raw)
	}
	_ = json.Unmarshal(raw, &got)
	if len(got.Channels) != 1 || got.Channels[0].Kind != "phone" || got.Channels[0].Plugin != "webhook" ||
		got.Channels[0].Config["url"] != url || time.Since(got.Channels[0].Secrets["secret"]) > time.Minute {
		t.Errorf("channels: %+v", got.Channels)
	}
	// ... and sealed in PG.
	var n int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM channel_secrets WHERE position('s3cret'::bytea IN value) > 0").Scan(&n); err != nil || n != 0 {
		t.Errorf("plaintext secret in PG: %d %v", n, err)
	}

	sendTest := func(token string) (int, string) {
		var out struct{ Code string }
		status := e.call("POST", token, "/channels/phone/test", map[string]string{"to": "+8613800001111"}, &out)
		return status, out.Code
	}
	if status, _ := sendTest(ro); status != 403 {
		t.Errorf("readonly test send: %d, want 403", status)
	}
	status, code := sendTest(owner)
	if status != 200 || !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Fatalf("test send: %d %q", status, code)
	}
	if got := <-codes; got != code {
		t.Errorf("webhook got %q, API said %q", got, code)
	}

	// Leaving a secret empty keeps the stored one.
	put["config"] = map[string]string{"url": url, "secret": ""}
	if code := e.call("PUT", owner, "/channels/phone", put, nil); code != 204 {
		t.Fatalf("PUT without secret: %d", code)
	}
	if status, code := sendTest(owner); status != 200 || <-codes != code {
		t.Errorf("after keeping the secret: %d", status)
	}

	// The receiver refuses: the admin sees why.
	put["config"] = map[string]string{"url": url, "secret": "other"}
	e.call("PUT", owner, "/channels/phone", put, nil)
	if status, _ := sendTest(owner); status != 502 {
		t.Errorf("failed delivery: %d, want 502", status)
	}

	if code := e.call("DELETE", owner, "/channels/phone", nil, nil); code != 204 {
		t.Errorf("DELETE: %d", code)
	}
	if e.get(ro, "/channels", &got); len(got.Channels) != 0 {
		t.Errorf("after DELETE: %+v", got.Channels)
	}
	if status, _ := sendTest(owner); status != 404 {
		t.Errorf("test send with no Channel: %d, want 404", status)
	}
}

func TestChannelSettingsAreChecked(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	put := func(kind, plugin string, config map[string]string) int {
		return e.call("PUT", owner, "/channels/"+kind, map[string]any{"plugin": plugin, "config": config}, nil)
	}
	smtp := map[string]string{"host": "127.0.0.1", "port": "2525", "from": "noreply@example.com"}
	for name, code := range map[string]int{
		"unknown plugin":  put("email", "carrier-pigeon", map[string]string{}),
		"SMTP for phones": put("phone", "smtp", smtp),
		"unknown kind":    put("fax", "webhook", map[string]string{"url": "https://h.example", "secret": "s"}),
		"missing field":   put("email", "smtp", map[string]string{"host": "h", "port": "25"}),
		"missing secret":  put("email", "webhook", map[string]string{"url": "https://h.example"}),
		"bad number":      put("email", "smtp", map[string]string{"host": "h", "port": "abc", "from": "a@example.com"}),
		"bad URL":         put("email", "webhook", map[string]string{"url": "ftp://h.example", "secret": "s"}),
		"plugin refuses":  put("email", "smtp", map[string]string{"host": "h", "port": "25", "from": "nope"}),
	} {
		if code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}

	// Switching plugin drops the old plugin's secrets.
	if code := put("email", "webhook", map[string]string{"url": "https://h.example", "secret": "s"}); code != 204 {
		t.Fatalf("webhook: %d", code)
	}
	if code := put("email", "smtp", smtp); code != 204 {
		t.Fatalf("smtp: %d", code)
	}
	var got channels
	e.get(owner, "/channels", &got)
	if len(got.Channels) != 1 || got.Channels[0].Plugin != "smtp" || len(got.Channels[0].Secrets) != 0 || got.Channels[0].Config["secret"] != "" {
		t.Errorf("after switching: %+v", got.Channels)
	}

	// Test codes go to a real phone number or email address only.
	for kind, to := range map[string]string{"email": "not-an-address", "phone": "13800001111"} {
		if code := e.call("POST", owner, "/channels/"+kind+"/test", map[string]string{"to": to}, nil); code != 422 {
			t.Errorf("test send to %s %q: %d, want 422", kind, to, code)
		}
	}
}
