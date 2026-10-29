package management_test

import (
	"context"
	"fmt"
	"maps"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
)

// Every Management API write audits itself (ADR 0025): each succeeds with
// exactly one event named 名词.动词, saying who did it. The table must have a
// row for every write in the OpenAPI document, so a new write that is not
// registered here fails the test.
func TestEveryWriteIsAudited(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "email:alice@example.com", "phone:+8613800001111")
	owner := e.token(e.owner, nil)
	o := &outbox{}
	mail := httptest.NewServer(o)
	t.Cleanup(mail.Close)
	api := "https://api.example"
	apiPath := "/apis/" + url.PathEscape(api)
	var clientID string
	by := map[string]any{"by": e.owner, "byType": "user"}
	with := func(kv ...any) map[string]any {
		m := maps.Clone(by)
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	call := func(method, path string, body any) func() int {
		return func() int { return e.call(method, owner, path, body, nil) }
	}

	rows := []auditRow{
		{op: "create-user", call: call("POST", "/users", map[string]string{"identifier": "bob@example.com", "password": "password1"}), event: "user.created"},
		{op: "put-channel", call: call("PUT", "/channels/email", map[string]any{"plugin": "webhook", "config": map[string]string{"url": mail.URL, "secret": "s"}}),
			event: "channel.saved", detail: with("kind", "email")},
		// The recipient is not recorded.
		{op: "test-channel", call: call("POST", "/channels/email/test", map[string]string{"to": "x@example.com"}),
			event: "channel.tested", detail: with("kind", "email")},
		{op: "send-invite", call: call("POST", "/users/ALICE/invite", nil), event: "invite.sent"},
		{op: "revoke-invite", call: call("DELETE", "/users/ALICE/invite", nil), event: "invite.revoked"},
		{op: "end-session", call: func() int {
			return e.call("DELETE", owner, "/users/ALICE/sessions/"+e.session("ALICE", "polaris-console", false), nil, nil)
		}, event: "session.ended"},
		{op: "disable-user", call: call("POST", "/users/ALICE/disable", nil), event: "user.disabled"},
		{op: "enable-user", call: call("POST", "/users/ALICE/enable", nil), event: "user.enabled"},
		{op: "reset-two-factor", setup: func() { e.twoFactorOn("ALICE") }, call: call("DELETE", "/users/ALICE/2fa", nil), event: "mfa.reset"},
		{op: "replace-identifier", call: call("PUT", "/users/ALICE/identifiers/username", map[string]string{"value": "alice"}), event: "identifier.replaced"},
		{op: "set-user-nickname", call: call("PATCH", "/users/ALICE/profile", map[string]string{"nickname": "A"}), event: "user.profile_updated"},
		{op: "remove-user-avatar", setup: func() { e.avatar("ALICE") }, call: call("DELETE", "/users/ALICE/avatar", nil), event: "user.avatar_removed"},
		{op: "remove-user-passkey", call: func() int {
			return e.call("DELETE", owner, "/users/ALICE/passkeys/"+e.passkey("ALICE", "k", false), nil, nil)
		}, event: "passkey.removed"},
		{op: "create-provider", call: call("POST", "/providers", google(nil)), event: "provider.created", detail: with("id", "google", "type", "oidc")},
		{op: "update-provider", call: call("PUT", "/providers/google", map[string]any{"name": "G", "config": google(nil)["config"]}),
			event: "provider.updated", detail: with("id", "google")},
		{op: "disable-provider", call: call("POST", "/providers/google/disable", nil), event: "provider.disabled", detail: with("id", "google")},
		{op: "enable-provider", call: call("POST", "/providers/google/enable", nil), event: "provider.enabled", detail: with("id", "google")},
		{op: "unbind-external-identity", setup: func() {
			if _, err := e.pool.Exec(context.Background(), `INSERT INTO external_identities (provider, subject, user_id) VALUES ('google', 'a', 'ALICE')`); err != nil {
				t.Fatal(err)
			}
		}, call: call("DELETE", "/users/ALICE/external-identities/google", nil), event: "external_identity.removed"},
		{op: "delete-provider", call: call("DELETE", "/providers/google", nil), event: "provider.deleted", detail: with("id", "google")},
		{op: "put-api", call: call("PUT", apiPath, map[string]string{"name": "Example"}), event: "api.saved", detail: with("api", api)},
		{op: "put-permission", call: call("PUT", apiPath+"/permissions/read", map[string]string{"name": "Read"}),
			event: "permission.saved", detail: with("api", api, "key", "read")},
		{op: "put-role", call: call("PUT", apiPath+"/roles/reader", map[string]any{"name": "Reader", "permissions": []string{"read"}}),
			event: "role.saved", detail: with("api", api, "key", "reader")},
		{op: "set-user-roles", call: call("PUT", "/users/ALICE/roles", map[string]any{"api": api, "roles": []string{"reader"}}), event: "roles.assigned"},
		{op: "create-application", call: func() int {
			var created struct{ Application application }
			code := e.call("POST", owner, "/applications", map[string]any{"type": "m2m", "settings": m2mSettings(api)}, &created)
			clientID = created.Application.ClientID
			return code
		}, event: "application.created"},
		{op: "set-application-roles", call: func() int {
			return e.call("PUT", owner, "/applications/"+clientID+"/roles", map[string]any{"roles": []string{"reader"}}, nil)
		}, event: "application_roles.assigned"},
		{op: "update-application", call: func() int {
			return e.call("PUT", owner, "/applications/"+clientID, m2mSettings(api), nil)
		}, event: "application.updated"},
		{op: "new-application-secret", call: func() int { return e.call("POST", owner, "/applications/"+clientID+"/secret", nil, nil) },
			event: "application.secret_regenerated"},
		{op: "set-application-auth-method", call: func() int {
			return e.call("POST", owner, "/applications/"+clientID+"/auth-method", map[string]string{"method": "client_secret_basic"}, nil)
		}, event: "application.auth_method_changed"},
		{op: "delete-application", call: func() int { return e.call("DELETE", owner, "/applications/"+clientID, nil, nil) },
			event: "application.deleted"},
		{op: "delete-role", call: call("DELETE", apiPath+"/roles/reader?force=true", nil), event: "role.deleted",
			detail: with("api", api, "key", "reader", "force", true)},
		{op: "delete-permission", call: call("DELETE", apiPath+"/permissions/read", nil), event: "permission.deleted",
			detail: with("api", api, "key", "read")},
		{op: "delete-api", call: call("DELETE", apiPath, nil), event: "api.deleted", detail: with("api", api, "force", false)},
		{op: "delete-channel", call: call("DELETE", "/channels/email", nil), event: "channel.deleted", detail: with("kind", "email")},
		{op: "delete-user", call: call("DELETE", "/users/ALICE", nil), event: "user.deleted"},
		{op: "put-settings", call: call("PUT", "/settings", settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, PasskeyLogin: true}),
			event: "settings.updated"},
		{op: "rotate-signing-keys", call: call("POST", "/signing-keys/rotate", nil), event: "keys.rotated"},
	}

	// Every write in the API has a row.
	var doc struct {
		Paths map[string]map[string]struct{ OperationID string }
	}
	if code := e.get("", "/openapi.json", &doc); code != 200 {
		t.Fatalf("openapi: %d", code)
	}
	for _, ops := range doc.Paths {
		for method, op := range ops {
			if method != "get" && !slices.ContainsFunc(rows, func(r auditRow) bool {
				return r.op == op.OperationID
			}) {
				t.Errorf("%s is not in the table: add a row, and audit it", op.OperationID)
			}
		}
	}

	for _, r := range rows {
		if r.setup != nil {
			r.setup()
		}
		var last int64
		if got := e.events("limit=1"); len(got) > 0 {
			last = got[0].ID
		}
		if code := r.call(); code/100 != 2 {
			t.Errorf("%s: %d", r.op, code)
			continue
		}
		var added []auditEvent
		for _, ev := range e.events("limit=10") {
			if ev.ID > last {
				added = append(added, ev)
			}
		}
		if len(added) != 1 || added[0].Event != r.event || added[0].Detail["by"] != e.owner {
			t.Errorf("%s: %+v, want one %s by the owner", r.op, added, r.event)
			continue
		}
		if r.detail != nil && !maps.Equal(fmtMap(added[0].Detail), fmtMap(r.detail)) {
			t.Errorf("%s detail: %v, want %v", r.op, added[0].Detail, r.detail)
		}
	}

	// A write that fails is not audited.
	before := len(e.events("limit=200"))
	if code := e.call("DELETE", owner, "/apis/"+url.PathEscape("https://none.example"), nil, nil); code != 404 {
		t.Errorf("delete an unknown API: %d", code)
	}
	if code := e.call("PUT", owner, "/channels/email", map[string]any{"plugin": "webhook", "config": map[string]string{"url": mail.URL, "secret": "s"}}, nil); code != 204 {
		t.Fatal(code)
	}
	o.mu.Lock()
	o.fail = true
	o.mu.Unlock()
	if code := e.call("POST", owner, "/channels/email/test", map[string]string{"to": "x@example.com"}, nil); code != 502 {
		t.Errorf("a test send that fails: %d", code)
	}
	if got := e.events("limit=200"); len(got) != before+1 || got[0].Event != "channel.saved" {
		t.Errorf("failed writes audited: %+v", got[:len(got)-before])
	}
}

type auditRow struct {
	op     string // operation ID
	setup  func() // what the write needs, which may audit too
	call   func() int
	event  string
	detail map[string]any // the whole detail, when the write has one worth pinning down
}

// fmtMap makes JSON values comparable.
func fmtMap(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}
