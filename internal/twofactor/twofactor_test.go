package twofactor_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/twofactor"
)

// code is what an authenticator shows for a Base32 secret at t (RFC 6238).
func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, at.Unix()/30)
	sum := mac.Sum(nil)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[sum[19]&0xf:])&0x7fffffff)%1_000_000)
}

// The checks signing in and reauthenticating rely on: a TOTP code within a
// step of now works once, never an earlier one after it; a recovery code
// works once, typed any which way.
func TestChecks(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err := sqlc.New(pool).CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	s := twofactor.New(pool, keyring)
	on := func() bool {
		t.Helper()
		on, err := s.On(ctx, "ALICE")
		if err != nil {
			t.Fatal(err)
		}
		return on
	}
	if on() {
		t.Error("on with no TOTP")
	}

	secret, err := s.Begin(ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if on() {
		t.Error("on before confirming")
	}
	now := time.Now()
	if err := s.CheckTOTP(ctx, "ALICE", code(t, secret, now)); !errors.Is(err, twofactor.ErrOff) {
		t.Errorf("before confirming: %v", err)
	}
	codes, err := s.Confirm(ctx, "ALICE", code(t, secret, now.Add(-30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if !on() {
		t.Error("off after confirming")
	}
	for _, c := range []string{code(t, secret, now.Add(-30*time.Second)), code(t, secret, now.Add(-90*time.Second))} {
		if err := s.CheckTOTP(ctx, "ALICE", c); !errors.Is(err, twofactor.ErrCode) {
			t.Errorf("used or too old a code: %v", err)
		}
	}
	if err := s.CheckTOTP(ctx, "ALICE", code(t, secret, now.Add(30*time.Second))); err != nil {
		t.Errorf("a step ahead: %v", err)
	}
	if err := s.CheckTOTP(ctx, "ALICE", code(t, secret, now)); !errors.Is(err, twofactor.ErrCode) {
		t.Errorf("before one already accepted: %v", err)
	}

	typed := " " + strings.ToUpper(strings.Replace(codes[0], "-", "", 1)) + " "
	if err := s.UseRecoveryCode(ctx, "ALICE", typed); err != nil {
		t.Errorf("recovery code %q: %v", typed, err)
	}
	if err := s.UseRecoveryCode(ctx, "ALICE", codes[0]); !errors.Is(err, twofactor.ErrRecoveryCode) {
		t.Errorf("recovery code again: %v", err)
	}
	if err := s.UseRecoveryCode(ctx, "ALICE", "aaaa-aaaa"); !errors.Is(err, twofactor.ErrRecoveryCode) {
		t.Errorf("made-up recovery code: %v", err)
	}
	if err := s.Disable(ctx, "ALICE", "mfa.reset", "ADMIN"); err != nil {
		t.Fatal(err)
	}
	if err := s.UseRecoveryCode(ctx, "ALICE", codes[1]); !errors.Is(err, twofactor.ErrRecoveryCode) {
		t.Errorf("recovery code after turning off: %v", err)
	}
}
