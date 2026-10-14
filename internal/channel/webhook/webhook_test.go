package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/stars-auth/internal/channel"
	_ "github.com/zibyn/stars-auth/internal/channel/webhook"
)

func TestPostsSignedTargetAndCode(t *testing.T) {
	type got struct {
		body []byte
		sig  string
	}
	posts := make(chan got, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		posts <- got{body, r.Header.Get("X-Stars-Signature")}
	}))
	defer ts.Close()

	ch, err := channel.Get("webhook").New(map[string]string{"url": ts.URL, "secret": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), "+8613800001111", "123456"); err != nil {
		t.Fatal(err)
	}
	p := <-posts

	var body map[string]string
	if err := json.Unmarshal(p.body, &body); err != nil || body["to"] != "+8613800001111" || body["code"] != "123456" {
		t.Errorf("body: %s", p.body)
	}
	// X-Stars-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
	ts1, v1, _ := strings.Cut(p.sig, ",v1=")
	sec, err := strconv.ParseInt(strings.TrimPrefix(ts1, "t="), 10, 64)
	if err != nil || time.Since(time.Unix(sec, 0)).Abs() > time.Minute {
		t.Errorf("signature timestamp: %q", p.sig)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(strings.TrimPrefix(ts1, "t=") + "."))
	mac.Write(p.body)
	if v1 != hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("signature: %q", p.sig)
	}
}

// 注册邀请带的是 link, 不是 code: 收信方按 {"to","link"} 认, 邮件里没有
// 验证码那一行。
func TestPostsLinkForAnInvite(t *testing.T) {
	posts := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		posts <- body
	}))
	defer ts.Close()

	ch, err := channel.Get("webhook").New(map[string]string{"url": ts.URL, "secret": "s"})
	if err != nil {
		t.Fatal(err)
	}
	link := "https://auth.example.com/invite?token=abc"
	if err := ch.SendLink(context.Background(), "alice@example.com", link); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(<-posts, &body); err != nil {
		t.Fatal(err)
	}
	if body["to"] != "alice@example.com" || body["link"] != link || len(body) != 2 {
		t.Errorf("body: %v", body)
	}
}

func TestNon2xxIsAnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer ts.Close()
	ch, err := channel.Get("webhook").New(map[string]string{"url": ts.URL, "secret": "s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), "a@example.com", "123456"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("err = %v, want one naming the 502", err)
	}
}
