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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
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
	if err := s.Disable(ctx, "ALICE", "mfa.reset", audit.User("ADMIN")); err != nil {
		t.Fatal(err)
	}
	if err := s.UseRecoveryCode(ctx, "ALICE", codes[1]); !errors.Is(err, twofactor.ErrRecoveryCode) {
		t.Errorf("recovery code after turning off: %v", err)
	}
}

// 两步验证 takes a TOTP, a Passkey only while the instance offers Passkey
// login, and the phone number and email added; a login's second step leaves
// out a code over its first factor's channel (ADR 0038).
func TestFactors(t *testing.T) {
	T, P, S, E := twofactor.FactorTOTP, twofactor.FactorPasskey, twofactor.FactorSMS, twofactor.FactorEmail
	all := twofactor.Factors{TOTP: true, Passkey: true, PasskeyLogin: true, SMS: true, Email: true}
	for _, c := range []struct {
		f           twofactor.Factors
		amr         []string
		usable, now []twofactor.Factor
	}{
		{twofactor.Factors{}, []string{"pwd"}, nil, nil},
		{twofactor.Factors{TOTP: true}, []string{"sms"}, []twofactor.Factor{T}, []twofactor.Factor{T}},
		{twofactor.Factors{Passkey: true}, []string{"pwd"}, nil, nil},
		{all, []string{"pwd"}, []twofactor.Factor{T, P, S, E}, []twofactor.Factor{T, P, S, E}},
		{all, []string{"fed"}, []twofactor.Factor{T, P, S, E}, []twofactor.Factor{T, P, S, E}},
		{all, []string{"sms"}, []twofactor.Factor{T, P, S, E}, []twofactor.Factor{T, P, E}},
		{all, []string{"otp"}, []twofactor.Factor{T, P, S, E}, []twofactor.Factor{T, P, S}},
		{twofactor.Factors{SMS: true}, []string{"sms"}, []twofactor.Factor{S}, nil},
	} {
		if got := c.f.Usable(); !slices.Equal(got, c.usable) {
			t.Errorf("%+v Usable() = %v, want %v", c.f, got, c.usable)
		}
		if got := c.f.SecondStep(c.amr); !slices.Equal(got, c.now) {
			t.Errorf("%+v SecondStep(%v) = %v, want %v", c.f, c.amr, got, c.now)
		}
	}
}

// Removing a factor is refused only when it is the one usable factor of
// 两步验证 on; one not usable now changes nothing (ADR 0038).
func TestLast(t *testing.T) {
	for _, c := range []struct {
		f    twofactor.Factors
		g    twofactor.Factor
		want bool
	}{
		{twofactor.Factors{On: true, SMS: true}, twofactor.FactorSMS, true},
		{twofactor.Factors{SMS: true}, twofactor.FactorSMS, false},
		{twofactor.Factors{On: true, SMS: true, Email: true}, twofactor.FactorSMS, false},
		{twofactor.Factors{On: true}, twofactor.FactorSMS, false},
		{twofactor.Factors{On: true, TOTP: true, Passkey: true}, twofactor.FactorTOTP, true},
		{twofactor.Factors{On: true, TOTP: true, Passkey: true}, twofactor.FactorPasskey, false},
		{twofactor.Factors{On: true, Passkey: true}, twofactor.FactorPasskey, false},
	} {
		if got := c.f.Last(c.g); got != c.want {
			t.Errorf("%+v Last(%s) = %v, want %v", c.f, c.g, got, c.want)
		}
	}
}

// A TOTP always satisfies 两步验证或 Passkey; a Passkey only while the
// instance offers Passkey login.
func TestSatisfied(t *testing.T) {
	for _, c := range []struct{ totp, passkey, passkeyLogin, want bool }{
		{true, false, false, true},
		{false, true, true, true},
		{false, true, false, false},
		{false, false, true, false},
	} {
		if got := twofactor.Satisfied(c.totp, c.passkey, c.passkeyLogin); got != c.want {
			t.Errorf("Satisfied(%v, %v, %v) = %v", c.totp, c.passkey, c.passkeyLogin, got)
		}
	}
}

// Unbinding the phone number, a factor, while the email is removed as the
// other leaves 两步验证 with one of them, never none: the unbinding finds
// the email left, then holds its transaction open while the removal, finding
// the phone number left, goes through; run again, the unbinding is refused
// (ADR 0038).
func TestUnbindWhileRemovingTheOtherFactor(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	q := sqlc.New(pool)
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	for kind, value := range map[string]string{"phone": "+8613800138000", "email": "alice@example.com"} {
		if err := q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: "ALICE", Kind: kind, Value: value}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO channels (kind, plugin, config, version) VALUES ($1, 'webhook', '{}', 1)", kind); err != nil {
			t.Fatal(err)
		}
	}
	s := twofactor.New(pool, keyring)
	for _, kind := range []string{"phone", "email"} {
		if err := s.AddCode(ctx, "ALICE", kind); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Enable(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}

	first := true
	err := identity.New(pool, keyring).RemoveIdentifier(ctx, "ALICE", "phone", func(q *sqlc.Queries) error {
		err := twofactor.FactorUnbound(ctx, q, "ALICE", "phone", audit.User("ALICE"))
		if first {
			first = false
			if err := s.RemoveCode(ctx, "ALICE", "email"); err != nil {
				t.Errorf("remove the email meanwhile: %v", err)
			}
		}
		return err
	})
	if !errors.Is(err, twofactor.ErrLastFactor) {
		t.Errorf("unbind the phone number: %v, want ErrLastFactor", err)
	}
	if f, err := s.SecondFactors(ctx, "ALICE"); err != nil || !f.On || len(f.Usable()) == 0 {
		t.Errorf("两步验证 left with no factor: %+v %v", f, err)
	}
}
