package account_test

import (
	"context"
	"testing"

	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/passkey/passkeytest"
)

// hooked adds an Application with a webhook.
func (e *env) hooked() {
	e.t.Helper()
	ctx := context.Background()
	if err := oidcstore.CreateApplication(ctx, e.pool, oidcstore.Application{ClientID: "hooked", Name: "hooked"}); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE applications SET webhook_url = 'https://rp.example/hook', webhook_secret = 'x' WHERE client_id = 'hooked'"); err != nil {
		e.t.Fatal(err)
	}
}

// queued checks and takes the deliveries queued since the last call: each
// the user.updated of ALICE, carrying nothing but the sub and what changed.
func (e *env) queued(what string, changed ...string) {
	e.t.Helper()
	var got []string
	if err := e.pool.QueryRow(context.Background(), `
		WITH d AS (DELETE FROM webhook_deliveries RETURNING payload)
		SELECT COALESCE(array_agg(d.payload->'data'->'changed'->>0), '{}') FROM d
		WHERE d.payload->>'type' = 'user.updated' AND ((d.payload->'data') - 'changed'::text) = '{"sub": "ALICE"}'::jsonb
		  AND jsonb_array_length(d.payload->'data'->'changed') = 1`).Scan(&got); err != nil {
		e.t.Fatal(err)
	}
	var left int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM webhook_deliveries WHERE kind = 'webhook'").Scan(&left); err != nil {
		e.t.Fatal(err)
	}
	if left != 0 || len(got) != len(changed) || (len(got) == 1 && got[0] != changed[0]) {
		e.t.Errorf("%s: queued %v and %d others, want %v", what, got, left, changed)
	}
}

// A User changing their own phone number or email queues user.updated;
// changing Credentials or External Identities does not.
func TestWebhookOnOwnChanges(t *testing.T) {
	e := start(t)
	e.hooked()
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()
	tok := e.signIn("ALICE", 0)

	e.call("POST", tok, "/v1/account/identifiers/phone/code", map[string]string{"value": "13900139000"}, nil)
	if c := e.call("PUT", tok, "/v1/account/identifiers/phone", map[string]string{"value": "13900139000", "code": e.inbox.take("+8613900139000")}, nil); c != 204 {
		t.Fatalf("change phone: %d", c)
	}
	e.queued("change phone", "phone")
	e.call("POST", tok, "/v1/account/identifiers/email/code", map[string]string{"value": "alice@example.com"}, nil)
	if c := e.call("PUT", tok, "/v1/account/identifiers/email", map[string]string{"value": "alice@example.com", "code": e.inbox.take("alice@example.com")}, nil); c != 204 {
		t.Fatalf("bind email: %d", c)
	}
	e.queued("bind email", "email")
	if c := e.call("DELETE", tok, "/v1/account/identifiers/email", nil, nil); c != 204 {
		t.Fatalf("unbind email: %d", c)
	}
	e.queued("unbind email", "email")

	if c := e.call("PUT", tok, "/v1/account/password", map[string]string{"password": "password1"}, nil); c != 204 {
		t.Fatalf("set password: %d", c)
	}
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	code, added := e.enroll(tok, a)
	if code != 200 {
		t.Fatalf("add Passkey: %d", code)
	}
	if c := e.call("DELETE", tok, "/v1/account/passkeys/"+added["id"].(string), nil, nil); c != 204 {
		t.Fatalf("delete Passkey: %d", c)
	}
	e.enableTwoFactor(tok)
	if c := e.call("DELETE", tok, "/v1/account/2fa", nil, nil); c != 204 {
		t.Fatalf("turn 两步验证 off: %d", c)
	}
	if q := e.redirect(tok, "/v1/account/providers/google/bind"); q.Get("bound") != "google" {
		t.Fatalf("bind Google: %v", q)
	}
	if c := e.call("DELETE", tok, "/v1/account/providers/google", nil, nil); c != 204 {
		t.Fatalf("unbind Google: %d", c)
	}
	e.queued("Credentials and External Identities")
}
