package login

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zibyn/stars-auth/internal/crypt"
	"github.com/zibyn/stars-auth/internal/db"
	"github.com/zibyn/stars-auth/internal/db/dbtest"
	"github.com/zibyn/stars-auth/internal/twofactor"
)

// TestNextStep pins the order every login runs after the first factor:
// 待激活, 两步验证, 绑手机号, 同意协议. The transports only render the step; the
// order itself lives in nextStep.
func TestNextStep(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, pool, keyring, "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	tf := twofactor.New(pool, keyring)

	seq := 0
	unique := func(prefix string) string {
		seq++
		return fmt.Sprintf("%s%d@example.com", prefix, seq)
	}
	phone := func() string {
		seq++
		return fmt.Sprintf("+86138%08d", seq)
	}
	active := func(t *testing.T, kind, value string) string {
		t.Helper()
		sub, err := s.ids.SignIn(ctx, kind, value)
		if err != nil {
			t.Fatal(err)
		}
		return sub
	}
	pending := func(t *testing.T) string {
		t.Helper()
		sub, err := s.ids.CreatePendingUser(ctx, unique("pending"), "password1")
		if err != nil {
			t.Fatal(err)
		}
		return sub
	}
	enableTOTP := func(t *testing.T, sub string) {
		t.Helper()
		secret, err := tf.Begin(ctx, sub)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tf.Confirm(ctx, sub, totpAt(secret, -1)); err != nil {
			t.Fatal(err)
		}
	}
	requirePhone := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "UPDATE settings SET require_phone = true"); err != nil {
			t.Fatal(err)
		}
	}
	terms := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE settings SET terms_version = 'v1',
			terms_url = 'https://example.com/terms', privacy_url = 'https://example.com/privacy'`); err != nil {
			t.Fatal(err)
		}
	}
	consent := func(t *testing.T, sub string) {
		t.Helper()
		if _, err := pool.Exec(ctx, "INSERT INTO consents (user_id, version, client_id) VALUES ($1, 'v1', 'test')", sub); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE settings SET require_phone = false,
			terms_version = '', terms_url = '', privacy_url = ''`); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name     string
		setup    func(*testing.T) (sub string, amr []string)
		signedIn bool
		want     step
	}{
		{
			name: "nothing left",
			setup: func(t *testing.T) (string, []string) {
				return active(t, "phone", phone()), []string{"pwd"}
			},
			want: stepDone,
		},
		{
			name: "待激活 before 两步验证 and the rest",
			setup: func(t *testing.T) (string, []string) {
				sub := pending(t)
				enableTOTP(t, sub)
				requirePhone(t)
				terms(t)
				return sub, []string{"pwd"}
			},
			want: stepSetPassword,
		},
		{
			name: "两步验证 before 同意协议 and 绑手机号",
			setup: func(t *testing.T) (string, []string) {
				sub := active(t, "email", unique("mfa"))
				enableTOTP(t, sub)
				requirePhone(t)
				terms(t)
				return sub, []string{"pwd"}
			},
			want: stepTOTP,
		},
		{
			name: "mfa in amr clears 两步验证",
			setup: func(t *testing.T) (string, []string) {
				sub := active(t, "email", unique("mfa-amr"))
				enableTOTP(t, sub)
				requirePhone(t)
				return sub, []string{"mfa"}
			},
			want: stepPhone,
		},
		{
			name: "同意协议 before 绑手机号",
			setup: func(t *testing.T) (string, []string) {
				requirePhone(t)
				terms(t)
				return active(t, "email", unique("phone")), []string{"pwd"}
			},
			want: stepConsent,
		},
		{
			name: "绑手机号 after 同意协议",
			setup: func(t *testing.T) (string, []string) {
				sub := active(t, "email", unique("consented"))
				consent(t, sub)
				requirePhone(t)
				terms(t)
				return sub, []string{"pwd"}
			},
			want: stepPhone,
		},
		{
			name: "同意协议 alone",
			setup: func(t *testing.T) (string, []string) {
				terms(t)
				return active(t, "phone", phone()), []string{"pwd"}
			},
			want: stepConsent,
		},
		{
			name: "already signed in skips 两步验证",
			setup: func(t *testing.T) (string, []string) {
				sub := active(t, "email", unique("signed-in"))
				enableTOTP(t, sub)
				return sub, []string{"pwd"}
			},
			signedIn: true,
			want:     stepDone,
		},
		{
			name: "already signed in still binds a phone",
			setup: func(t *testing.T) (string, []string) {
				requirePhone(t)
				return active(t, "email", unique("signed-in-phone")), []string{"pwd"}
			},
			signedIn: true,
			want:     stepPhone,
		},
		{
			name: "already signed in still agrees to the terms",
			setup: func(t *testing.T) (string, []string) {
				terms(t)
				return active(t, "phone", phone()), []string{"pwd"}
			},
			signedIn: true,
			want:     stepConsent,
		},
	}

	names := map[step]string{
		stepDone: "done", stepSetPassword: "setPassword", stepTOTP: "totp",
		stepPhone: "phone", stepConsent: "consent",
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reset(t)
			sub, amr := tc.setup(t)
			got, err := s.nextStep(ctx, sub, amr, tc.signedIn)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("nextStep = %s, want %s", names[got], names[tc.want])
			}
		})
	}
}

// totpAt is what an authenticator shows for secret, steps 30-second steps
// from now (RFC 6238).
func totpAt(secret string, steps int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, time.Now().Unix()/30+steps)
	sum := mac.Sum(nil)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[sum[19]&0xf:])&0x7fffffff)%1_000_000)
}
