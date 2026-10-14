// Package smtp is the email Channel for any SMTP server. Port 465 speaks TLS
// from the start; other ports must offer STARTTLS, except on localhost.
package smtp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/zibyn/stars-auth/internal/channel"
)

func init() {
	channel.Register(channel.Plugin{
		Key:   "smtp",
		Name:  "SMTP",
		Kinds: []string{"email"},
		Fields: []channel.Field{
			{Key: "host", Label: "服务器", Type: "text", Help: "如 smtp.qq.com"},
			{Key: "port", Label: "端口", Type: "number", Help: "465 直接走 TLS;其他端口须支持 STARTTLS"},
			{Key: "username", Label: "用户名", Type: "text", Optional: true},
			{Key: "password", Label: "密码", Type: "text", Secret: true, Optional: true},
			{Key: "from", Label: "发件人", Type: "text", Help: "如 Stars Auth <noreply@example.com>"},
		},
		New: newSMTP,
	})
}

type mailer struct {
	host, port string
	auth       smtp.Auth
	from       *mail.Address
}

func newSMTP(c map[string]string) (channel.Channel, error) {
	port, err := strconv.Atoi(c["port"])
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("端口须为 1–65535")
	}
	from, err := mail.ParseAddress(c["from"])
	if err != nil {
		return nil, errors.New("发件人须为邮箱地址,如 Stars Auth <noreply@example.com>")
	}
	s := &mailer{host: c["host"], port: strconv.Itoa(port), from: from}
	if c["username"] != "" {
		if c["password"] == "" {
			return nil, errors.New("填了用户名就要填密码")
		}
		s.auth = smtp.PlainAuth("", c["username"], c["password"], c["host"])
	}
	return s, nil
}

func (s *mailer) Send(ctx context.Context, to, code string) error {
	return s.deliver(ctx, to, message(s.from, to,
		mime.BEncoding.Encode("utf-8", "验证码 "+code),
		fmt.Sprintf("你的验证码是 %s,5 分钟内有效。\r\n如非本人操作,请忽略本邮件。\r\n", code)))
}

// SendLink sends a 注册邀请: the link, and no code line (a code in an email
// that also carries a link is one more secret in the same mailbox for no
// reason).
func (s *mailer) SendLink(ctx context.Context, to, link string) error {
	return s.deliver(ctx, to, message(s.from, to,
		mime.BEncoding.Encode("utf-8", "邀请你设置密码"),
		fmt.Sprintf("点开下面的链接,设置你自己的密码。链接 7 天内有效,只能用一次。\r\n\r\n%s\r\n\r\n设置完就能直接使用,不用再注册。\r\n如非本人操作,请忽略本邮件。\r\n", link)))
}

func (s *mailer) deliver(ctx context.Context, to string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addr := net.JoinHostPort(s.host, s.port)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsConfig := &tls.Config{ServerName: s.host}
	if s.port == "465" {
		conn = tls.Client(conn, tlsConfig)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	if s.port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return err
			}
		} else if !loopback(s.host) { // codes are secrets; no cleartext off this machine
			return errors.New("服务器不支持 STARTTLS,请改用 465 端口或支持 TLS 的服务器")
		}
	}
	if s.auth != nil {
		if err := c.Auth(s.auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func message(from *mail.Address, to, subject, body string) []byte {
	var b strings.Builder
	for _, h := range [][2]string{
		{"From", from.String()},
		{"To", to},
		{"Subject", subject},
		{"Date", time.Now().Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "base64"},
	} {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	// MIME caps base64 lines at 76 characters.
	for enc := base64.StdEncoding.EncodeToString([]byte(body)); enc != ""; {
		n := min(76, len(enc))
		b.WriteString(enc[:n] + "\r\n")
		enc = enc[n:]
	}
	return []byte(b.String())
}
