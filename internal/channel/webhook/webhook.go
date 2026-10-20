// Package webhook is the Channel for any service Polaris has no plugin
// for: it POSTs {"to", "code"} to the admin's URL, or {"to", "link"} for a
// 注册邀请, signed with a shared secret.
//
// X-Stars-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
//
// The receiver should reject stale t to stop replays.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/zibyn/stars-auth/internal/channel"
)

func init() {
	channel.Register(channel.Plugin{
		Key:   "webhook",
		Name:  "Webhook",
		Kinds: []string{"phone", "email"},
		Fields: []channel.Field{
			{Key: "url", Label: "URL", Type: "url", Help: `收到 POST {"to", "code"}(注册邀请为 {"to", "link"}),返回 2xx 即视为送达`},
			{Key: "secret", Label: "签名密钥", Type: "text", Secret: true,
				Help: "X-Stars-Signature: t=<秒>,v1=<hex HMAC-SHA256(密钥, \"<t>.<body>\")>"},
		},
		New: func(c map[string]string) (channel.Channel, error) {
			return &webhook{url: c["url"], secret: []byte(c["secret"])}, nil
		},
	})
}

type webhook struct {
	url    string
	secret []byte
}

var client = &http.Client{Timeout: 10 * time.Second}

func (w *webhook) Send(ctx context.Context, to, code string) error {
	return w.post(ctx, map[string]string{"to": to, "code": code})
}

func (w *webhook) SendLink(ctx context.Context, to, link string) error {
	return w.post(ctx, map[string]string{"to": to, "link": link})
}

func (w *webhook) post(ctx context.Context, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, w.secret)
	mac.Write([]byte(t + "."))
	mac.Write(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stars-Signature", "t="+t+",v1="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: %s", resp.Status)
	}
	return nil
}
