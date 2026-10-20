package smtp_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"net"
	"net/mail"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/channel"
	_ "github.com/zibyn/polaris/internal/channel/smtp"
)

type received struct {
	auth, from string
	rcpt       []string
	data       string
}

// server is a local SMTP server that accepts one message per connection,
// with AUTH PLAIN and no TLS.
func server(t *testing.T) (port string, got chan received) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got = make(chan received, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, got)
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, got
}

func serve(conn net.Conn, got chan received) {
	defer conn.Close() //nolint:errcheck
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	var m received
	say("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch {
		case cmd == "EHLO":
			say("250-test")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(strings.ToUpper(line), "AUTH PLAIN "):
			b, _ := base64.StdEncoding.DecodeString(line[len("AUTH PLAIN "):])
			m.auth = string(b)
			say("235 ok")
		case cmd == "MAIL":
			m.from = line
			say("250 ok")
		case cmd == "RCPT":
			m.rcpt = append(m.rcpt, line)
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.data = b.String()
			say("250 ok")
			got <- m
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func TestSendsCodeByMail(t *testing.T) {
	port, got := server(t)
	ch, err := channel.Get("smtp").New(map[string]string{
		"host": "127.0.0.1", "port": port, "username": "mailer", "password": "pw",
		"from": "Polaris <noreply@example.com>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), "alice@example.com", "123456"); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if m.auth != "\x00mailer\x00pw" {
		t.Errorf("auth: %q", m.auth)
	}
	if m.from != "MAIL FROM:<noreply@example.com>" || len(m.rcpt) != 1 || m.rcpt[0] != "RCPT TO:<alice@example.com>" {
		t.Errorf("envelope: %q %q", m.from, m.rcpt)
	}
	msg, err := mail.ReadMessage(strings.NewReader(m.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, msg.Body))
	if msg.Header.Get("To") != "alice@example.com" || !strings.Contains(subject, "123456") || !strings.Contains(string(body), "123456") {
		t.Errorf("message:\n%s\nsubject %q body %q", m.data, subject, body)
	}
}

func TestNoAuthWithoutUsername(t *testing.T) {
	port, got := server(t)
	ch, err := channel.Get("smtp").New(map[string]string{"host": "127.0.0.1", "port": port, "from": "noreply@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), "bob@example.com", "654321"); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.auth != "" {
		t.Errorf("authenticated without a username: %q", m.auth)
	}
}

func TestRejectsBadSettings(t *testing.T) {
	for name, c := range map[string]map[string]string{
		"port":   {"host": "h", "port": "99999", "from": "a@example.com"},
		"from":   {"host": "h", "port": "25", "from": "not an address"},
		"no pwd": {"host": "h", "port": "25", "from": "a@example.com", "username": "u"},
	} {
		if _, err := channel.Get("smtp").New(c); err == nil {
			t.Errorf("%s: accepted %v", name, c)
		}
	}
}

// 注册邀请的邮件只有链接, 没有验证码那一行: 同一封信里多一个密钥, 对收信人
// 没有任何好处。
func TestSendsInviteLinkWithoutACode(t *testing.T) {
	port, got := server(t)
	ch, err := channel.Get("smtp").New(map[string]string{"host": "127.0.0.1", "port": port, "from": "Polaris <noreply@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	link := "https://auth.example.com/invite?token=abcdef"
	if err := ch.SendLink(context.Background(), "alice@example.com", link); err != nil {
		t.Fatal(err)
	}
	m := <-got
	msg, err := mail.ReadMessage(strings.NewReader(m.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, msg.Body))
	if !strings.Contains(subject, "邀请") || !strings.Contains(string(body), link) {
		t.Errorf("subject %q body %q", subject, body)
	}
	if strings.Contains(string(body), "验证码") {
		t.Errorf("an invite carries a code line:\n%s", body)
	}
}
