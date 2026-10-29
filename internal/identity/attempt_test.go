package identity

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Deleting an account keeps its audit events, with no IP or UA left in any.
func TestDeleteScrubsIPAndUAFromAudit(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)
	sub, err := s.SignIn(ctx, "phone", "+8613800138000")
	if err != nil {
		t.Fatal(err)
	}
	a := Attempt{ClientID: "rp", IP: "192.0.2.1", UA: "Safari"}
	if err := s.LoginSucceeded(ctx, a, sub, []string{"sms"}); err != nil {
		t.Fatal(err)
	}
	if err := s.loginFailed(ctx, a, sub, "code", ErrWrongCode); err != ErrWrongCode { //nolint:errorlint // returned as is
		t.Fatal(err)
	}
	if err := s.LoginSucceeded(ctx, a, "SOMEONE-ELSE", []string{"sms"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, sub); err != nil {
		t.Fatal(err)
	}
	var n, withIP int
	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE detail ? 'ip' OR detail ? 'ua') FROM audit_log
		WHERE sub = $1 AND event IN ('login.succeeded', 'login.failed')`, sub).Scan(&n, &withIP); err != nil {
		t.Fatal(err)
	}
	if n != 2 || withIP != 0 {
		t.Errorf("after deletion: %d login events, %d with IP or UA", n, withIP)
	}
	var client string
	if err := s.pool.QueryRow(ctx, `SELECT detail ->> 'client_id' FROM audit_log WHERE sub = $1 AND event = 'login.failed'`, sub).Scan(&client); err != nil || client != "rp" {
		t.Errorf("other fields: %q %v", client, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE sub = 'SOMEONE-ELSE' AND detail ? 'ip'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("another User's events scrubbed: %d %v", n, err)
	}
}

// failedLogins lists sub's login.failed events as method/client_id.
func failedLogins(t *testing.T, s *Store, sub string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT detail->>'method', detail->>'client_id' FROM audit_log
		WHERE event = 'login.failed' AND sub IS NOT DISTINCT FROM $1 ORDER BY id`, sub)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var method, client string
		if err := rows.Scan(&method, &client); err != nil {
			t.Fatal(err)
		}
		out = append(out, method+"/"+client)
	}
	return out
}

func TestPasswordAuditsAWrongOne(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub := owner(t, s)
	a := Attempt{ClientID: "rp", IP: "192.0.2.1"}
	if _, err := s.Password(ctx, a, "owner", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if got, err := s.Password(ctx, a, "owner", "password1"); got != sub || err != nil {
		t.Fatal(got, err)
	}
	if _, err := s.Password(ctx, a, "nobody", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if got := failedLogins(t, s, sub); !slices.Equal(got, []string{"password/rp"}) {
		t.Errorf("login.failed: %v", got)
	}
	if n := audited(t, s, "login.failed"); n != 1 {
		t.Errorf("%d login.failed in all, an unknown login's included", n)
	}
}

func TestEveryCheckWantsAClientID(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub := owner(t, s)
	ran := false
	check := func() error { ran = true; return nil }
	if _, err := s.Password(ctx, Attempt{IP: "192.0.2.1"}, "owner", "password1"); err == nil {
		t.Error("Password with no ClientID")
	}
	if err := s.Code(ctx, Attempt{IP: "192.0.2.1"}, "+8613800138000", "", check); err == nil {
		t.Error("Code with no ClientID")
	}
	if err := s.SecondFactor(ctx, Attempt{IP: "192.0.2.1"}, sub, false, check); err == nil {
		t.Error("SecondFactor with no ClientID")
	}
	if ran {
		t.Error("a check ran")
	}
}

func TestCodeAuditsOnWhomItWouldSignIn(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	holder, err := s.SignIn(ctx, "phone", "+8613800138000")
	if err != nil {
		t.Fatal(err)
	}
	a := Attempt{ClientID: "rp", IP: "192.0.2.1"}
	wrong := func() error { return ErrWrongCode }
	// The holder of the Identifier.
	if err := s.Code(ctx, a, "+8613800138000", "", wrong); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	// A pending login binding it: the pending User, not the holder.
	if err := s.Code(ctx, a, "+8613800138000", "PENDING", wrong); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	// Nobody's: nothing to audit.
	if err := s.Code(ctx, a, "+8613900139000", "", wrong); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	// A right code audits nothing.
	if err := s.Code(ctx, a, "+8613800138000", "", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := failedLogins(t, s, holder); !slices.Equal(got, []string{"code/rp"}) {
		t.Errorf("holder: %v", got)
	}
	if got := failedLogins(t, s, "PENDING"); !slices.Equal(got, []string{"code/rp"}) {
		t.Errorf("pending: %v", got)
	}
	if n := audited(t, s, "login.failed"); n != 2 {
		t.Errorf("%d login.failed in all", n)
	}
}

func TestSecondFactorAuditsTheMethod(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub := owner(t, s)
	a := Attempt{ClientID: "rp", IP: "192.0.2.1"}
	if err := s.SecondFactor(ctx, a, sub, false, func() error { return ErrWrongTOTP }); !errors.Is(err, ErrWrongTOTP) {
		t.Fatal(err)
	}
	if err := s.SecondFactor(ctx, a, sub, true, func() error { return ErrWrongRecoveryCode }); !errors.Is(err, ErrWrongRecoveryCode) {
		t.Fatal(err)
	}
	if got := failedLogins(t, s, sub); !slices.Equal(got, []string{"totp/rp", "recovery_code/rp"}) {
		t.Errorf("login.failed: %v", got)
	}
}
