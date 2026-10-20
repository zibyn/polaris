// Package aliyun is the SMS Channel on Aliyun's 号码认证服务「短信认证」, the
// one Chinese SMS route open to individuals: Aliyun lends the signature and
// template. Polaris passes its own code to SendSmsVerifyCode and never
// calls CheckSmsVerifyCode. Mainland (+86) numbers only.
package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zibyn/stars-auth/internal/channel"
)

func init() {
	channel.Register(channel.Plugin{
		Key:   "aliyun-pnvs-sms",
		Name:  "阿里云短信认证",
		Kinds: []string{"phone"},
		Fields: []channel.Field{
			{Key: "accessKeyId", Label: "AccessKey ID", Type: "text"},
			{Key: "accessKeySecret", Label: "AccessKey Secret", Type: "text", Secret: true},
			{Key: "signName", Label: "签名", Type: "text", Help: "号码认证控制台赠送的签名;只能发往中国大陆 +86 号码"},
			{Key: "templateCode", Label: "模板 Code", Type: "text", Help: "与签名配套的赠送模板,选登录/注册场景"},
		},
		New: func(c map[string]string) (channel.Channel, error) {
			return &sms{id: c["accessKeyId"], secret: c["accessKeySecret"], sign: c["signName"], template: c["templateCode"]}, nil
		},
	})
}

var endpoint = "https://dypnsapi.aliyuncs.com/"

var client = &http.Client{Timeout: 10 * time.Second}

type sms struct{ id, secret, sign, template string }

func (s *sms) Send(ctx context.Context, to, code string) error {
	phone, ok := strings.CutPrefix(to, "+86")
	if !ok {
		return errors.New("阿里云短信认证只能发往中国大陆号码")
	}
	tp, err := json.Marshal(map[string]string{"code": code, "min": "5"})
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	p := url.Values{
		"Action":           {"SendSmsVerifyCode"},
		"Version":          {"2017-05-25"},
		"Format":           {"JSON"},
		"AccessKeyId":      {s.id},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
		"SignatureNonce":   {hex.EncodeToString(nonce)},
		"Timestamp":        {time.Now().UTC().Format("2006-01-02T15:04:05Z")},
		"PhoneNumber":      {phone},
		"SignName":         {s.sign},
		"TemplateCode":     {s.template},
		"TemplateParam":    {string(tp)},
	}
	p.Set("Signature", sign(http.MethodPost, p, s.secret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(p.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var r struct{ Code, Message string }
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("aliyun: %s", resp.Status)
	}
	if r.Code != "OK" {
		return fmt.Errorf("aliyun: %s %s", r.Code, r.Message)
	}
	return nil
}

func (s *sms) SendLink(context.Context, string, string) error {
	// The 号码认证 template is a code-and-minutes one the sender does not get
	// to write, and there is no invitation template to borrow; a link that
	// only fits the code slot would go out as a garbled code. Invitations are
	// email-only for now.
	return errors.New("阿里云短信认证投递不了注册邀请:邀请只支持邮箱")
}

// sign is Aliyun's RPC signature, version 1.0 (HMAC-SHA1).
func sign(method string, p url.Values, secret string) string {
	// Encode sorts by key; re-encode each pair the way Aliyun wants.
	pairs := strings.Split(p.Encode(), "&")
	for i, kv := range pairs {
		k, v, _ := strings.Cut(kv, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		pairs[i] = escape(k) + "=" + escape(v)
	}
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(method + "&" + escape("/") + "&" + escape(strings.Join(pairs, "&"))))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func escape(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}
