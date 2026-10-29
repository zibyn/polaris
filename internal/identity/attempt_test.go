package identity

import (
	"context"
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
	if err := s.LoginFailed(ctx, a, sub, "code", ErrWrongCode); err != ErrWrongCode { //nolint:errorlint // returned as is
		t.Fatal(err)
	}
	if err := s.LoginSucceeded(ctx, a, "SOMEONE-ELSE", []string{"sms"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, sub, sub); err != nil {
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
