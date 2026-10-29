package management_test

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/identity"
)

type auditEvent struct {
	ID     int64
	At     time.Time
	Event  string
	Sub    string
	User   string
	ByUser string
	Detail map[string]any
}

// events reads the audit log through the API, newest first.
func (e *env) events(query string) []auditEvent {
	e.t.Helper()
	var out struct{ Events []auditEvent }
	if code := e.get(e.token(e.owner, nil), "/audit?"+query, &out); code != 200 {
		e.t.Fatalf("audit: %d", code)
	}
	return out.Events
}

// audited returns the newest event named event, failing if there is none.
func (e *env) audited(event string) auditEvent {
	e.t.Helper()
	got := e.events("event=" + url.QueryEscape(event))
	if len(got) == 0 {
		e.t.Fatalf("no %s event", event)
	}
	return got[0]
}

func TestAuditShowsWhoByTheirPrimaryIdentifier(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "username:alice", "email:alice@example.com", "phone:+8613800000001")
	owner := e.token(e.owner, nil)

	if code := e.call("POST", owner, "/users/ALICE/disable", nil, nil); code != 204 {
		t.Fatalf("disable ALICE: %d", code)
	}
	if ev := e.audited("user.disabled"); ev.User != "+8613800000001" || ev.ByUser != "owner" {
		t.Errorf("phone comes first, then the admin's username: %+v", ev)
	}
	if code := e.call("POST", owner, "/signing-keys/rotate", nil, nil); code != 204 {
		t.Fatalf("rotate keys: %d", code)
	}
	if ev := e.audited("keys.rotated"); ev.User != "" || ev.ByUser != "owner" {
		t.Errorf("no User: %+v", ev)
	}
	if code := e.call("DELETE", owner, "/users/ALICE", nil, nil); code != 204 {
		t.Fatalf("delete ALICE: %d", code)
	}
	if ev := e.audited("user.deleted"); ev.User != "" || ev.Sub != "ALICE" {
		t.Errorf("deleted User: %+v", ev)
	}

	// An admin who is gone: byUser goes too.
	e.user("ADMIN", []string{"admin"}, "email:admin@example.com")
	e.user("BOB", nil, "username:bob")
	if code := e.call("POST", e.token("ADMIN", nil), "/users/BOB/disable", nil, nil); code != 204 {
		t.Fatalf("admin disables BOB: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/ADMIN", nil, nil); code != 204 {
		t.Fatalf("delete ADMIN: %d", code)
	}
	if ev := e.audited("user.disabled"); ev.User != "bob" || ev.ByUser != "" || ev.Detail["by"] != "ADMIN" {
		t.Errorf("deleted admin: %+v", ev)
	}

	// Done by the system: no by, no byUser.
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO audit_log (event, sub, detail) VALUES ('refresh_token.reused', 'BOB', '{"session": "S1"}')`); err != nil {
		t.Fatal(err)
	}
	if ev := e.audited("refresh_token.reused"); ev.User != "bob" || ev.ByUser != "" {
		t.Errorf("no by: %+v", ev)
	}
}

// The audit types the operator: a User, or an M2M Application calling as
// itself, whose client_id then stands where a User's sub would (ADR 0015).
// An Application Role change is its own event, with its detail.
func TestAuditTypesAnApplicationOperator(t *testing.T) {
	e := start(t)
	e.trackAPI()
	e.user("ALICE", nil, "email:alice@example.com")
	owner := e.token(e.owner, nil)
	// It holds admin's Permissions on the Management API, so it may write.
	app := e.m2mApp(identity.ManagementAPI, "admin")

	if code := e.call("POST", owner, "/users/ALICE/disable", nil, nil); code != 204 {
		t.Fatalf("a User admin disables: %d", code)
	}
	if ev := e.audited("user.disabled"); ev.Detail["by"] != e.owner || ev.Detail["byType"] != "user" {
		t.Errorf("a User's write: %+v", ev)
	}

	// A User's erase of an Application's Roles, then the Application's own
	// restore: the event names the Application and the Roles either way.
	target := e.m2mApp(track)
	if code := e.call("PUT", owner, "/applications/"+target+"/roles", map[string]any{"roles": []string{}}, nil); code != 204 {
		t.Fatalf("a User clears Roles: %d", code)
	}
	if ev := e.audited("application_roles.assigned"); ev.Sub != "" || ev.Detail["clientId"] != target ||
		ev.Detail["api"] != track || fmt.Sprint(ev.Detail["roles"]) != "[]" ||
		ev.Detail["by"] != e.owner || ev.Detail["byType"] != "user" {
		t.Errorf("a User's Role change: %+v", ev)
	}
	if code := e.call("PUT", e.token(app, nil), "/applications/"+target+"/roles", map[string]any{"roles": []string{"viewer"}}, nil); code != 204 {
		t.Fatalf("the Application sets its own Roles: %d", code)
	}
	// by is the Application's client_id, typed; no User bears it, so nothing
	// resolves a byUser.
	if ev := e.audited("application_roles.assigned"); ev.Detail["clientId"] != target ||
		fmt.Sprint(ev.Detail["roles"]) != "[viewer]" ||
		ev.Detail["by"] != app || ev.Detail["byType"] != "application" || ev.ByUser != "" {
		t.Errorf("an Application's write: %+v", ev)
	}
}

func TestAdminDisablesAndRestoresAUser(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "email:alice@example.com")
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO sessions (user_id, auth_time, amr) VALUES ('ALICE', now(), '{pwd}'), ('ALICE', now(), '{sms}')`); err != nil {
		t.Fatal(err)
	}

	if code := e.call("POST", ro, "/users/ALICE/disable", nil, nil); code != 403 {
		t.Errorf("readonly: %d", code)
	}
	if code := e.call("POST", owner, "/users/NOPE/disable", nil, nil); code != 404 {
		t.Errorf("unknown User: %d", code)
	}
	if code := e.call("POST", owner, "/users/ALICE/disable", nil, nil); code != 204 {
		t.Fatalf("disable: %d", code)
	}
	var u struct{ DisabledAt *time.Time }
	if e.get(owner, "/users/ALICE", &u); u.DisabledAt == nil {
		t.Error("detail does not show disabled")
	}
	var sessions struct{ Sessions []struct{ Active bool } }
	e.get(owner, "/users/ALICE/sessions", &sessions)
	for _, s := range sessions.Sessions {
		if s.Active {
			t.Error("a Session survived disabling")
		}
	}
	if ev := e.audited("user.disabled"); ev.Sub != "ALICE" || ev.Detail["by"] != e.owner {
		t.Errorf("audit: %+v", ev)
	}

	if code := e.call("POST", owner, "/users/ALICE/enable", nil, nil); code != 204 {
		t.Fatalf("enable: %d", code)
	}
	u.DisabledAt = nil
	if e.get(owner, "/users/ALICE", &u); u.DisabledAt != nil {
		t.Error("still disabled")
	}
	if ev := e.audited("user.enabled"); ev.Sub != "ALICE" {
		t.Errorf("audit: %+v", ev)
	}

	// Acting on an admin takes admin-roles:assign, which admins lack.
	e.user("ADMIN", []string{"admin"})
	admin := e.token("ADMIN", nil)
	if code := e.call("POST", admin, "/users/RO/disable", nil, nil); code != 403 {
		t.Errorf("admin disables an admin: %d", code)
	}
	if code := e.call("PUT", admin, "/users/RO/identifiers/email", map[string]string{"value": "ro@example.com"}, nil); code != 403 {
		t.Errorf("admin replaces an admin's email: %d", code)
	}
	if code := e.call("POST", admin, "/users/ALICE/disable", nil, nil); code != 204 {
		t.Errorf("admin disables a User: %d", code)
	}

	// A disabled admin is no admin, even with a valid token.
	e.call("POST", owner, "/users/RO/disable", nil, nil)
	if code := e.get(ro, "/users", nil); code != 403 {
		t.Errorf("disabled admin: %d", code)
	}
}

// identity refuses to lose the last usable owner; each write that could
// answers that with a 409.
func TestLastOwnerIsA409(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	for _, op := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/users/" + e.owner + "/disable", nil},
		{"DELETE", "/users/" + e.owner, nil},
		{"PUT", "/users/" + e.owner + "/roles", map[string]any{"api": identity.ManagementAPI, "roles": []string{"admin"}}},
	} {
		if code := e.call(op.method, owner, op.path, op.body, nil); code != 409 {
			t.Errorf("%s %s: %d, want 409", op.method, op.path, code)
		}
	}
}

func TestAdminDeletesAUser(t *testing.T) {
	e := start(t)
	e.user("ALICE", []string{"readonly"}, "email:alice@example.com")
	owner := e.token(e.owner, nil)

	if code := e.call("DELETE", owner, "/users/ALICE", nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := e.get(owner, "/users/ALICE", nil); code != 404 {
		t.Errorf("after delete: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/ALICE", nil, nil); code != 404 {
		t.Errorf("delete again: %d", code)
	}
	// The Identifier is free again.
	e.user("ALICE2", nil, "email:alice@example.com")
	if ev := e.audited("user.deleted"); ev.Sub != "ALICE" || ev.Detail["by"] != e.owner {
		t.Errorf("audit: %+v", ev)
	}
}

func TestAdminReplacesAnIdentifier(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "email:alice@example.com")
	e.user("BOB", nil, "phone:+8613800002222")
	owner := e.token(e.owner, nil)
	put := func(sub, kind, value string) int {
		return e.call("PUT", owner, "/users/"+sub+"/identifiers/"+kind, map[string]string{"value": value}, nil)
	}

	if code := put("ALICE", "email", "  Alice@New.example "); code != 204 {
		t.Fatalf("replace email: %d", code)
	}
	if code := put("ALICE", "phone", "138 0000 1111"); code != 204 {
		t.Fatalf("add phone: %d", code)
	}
	if code := put("ALICE", "username", "Alice"); code != 204 {
		t.Fatalf("add username: %d", code)
	}
	var u user
	e.get(owner, "/users/ALICE", &u)
	want := map[string]string{"email": "alice@new.example", "phone": "+8613800001111", "username": "alice"}
	if len(u.Identifiers) != 3 {
		t.Errorf("identifiers: %+v", u.Identifiers)
	}
	for _, id := range u.Identifiers {
		if want[id.Kind] != id.Value {
			t.Errorf("%s = %q, want %q", id.Kind, id.Value, want[id.Kind])
		}
	}

	for name, tc := range map[string]struct {
		sub, kind, value string
		want             int
	}{
		"another User's": {"ALICE", "phone", "+8613800002222", 409},
		"not an email":   {"ALICE", "email", "nope", 422},
		"phone as email": {"ALICE", "email", "13800003333", 422},
		"bad username":   {"ALICE", "username", "a@b", 422},
		"unknown kind":   {"ALICE", "fax", "1", 422},
		"unknown User":   {"NOPE", "email", "x@example.com", 404},
	} {
		if code := put(tc.sub, tc.kind, tc.value); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	// The audit names the kind, never the values.
	if ev := e.audited("identifier.replaced"); ev.Sub != "ALICE" || ev.Detail["kind"] != "username" || ev.Detail["by"] != e.owner || ev.Detail["byType"] != "user" || len(ev.Detail) != 3 {
		t.Errorf("audit: %+v", ev)
	}
}

func TestAuditFilters(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil)
	e.user("BOB", nil)
	e.user("RO", []string{"readonly"})
	e.user("NOAUDIT", []string{"admin"})
	if _, err := e.pool.Exec(context.Background(), `
		DELETE FROM role_permissions WHERE role = 'admin' AND permission = 'audit:read';
		INSERT INTO audit_log (event, sub, detail, at) VALUES
			('user.disabled', 'ALICE', '{"by": "RO"}', now() - interval '2 days'),
			('user.disabled', 'BOB', '{"by": "RO"}', now() - interval '1 day'),
			('user.enabled', 'BOB', '{}', now())`); err != nil {
		t.Fatal(err)
	}
	if code := e.get(e.token("NOAUDIT", nil), "/audit", nil); code != 403 {
		t.Errorf("without audit:read: %d", code)
	}
	if code := e.get(e.token("RO", nil), "/audit", nil); code != 200 {
		t.Errorf("readonly: %d", code)
	}
	since := url.QueryEscape(time.Now().Add(-36 * time.Hour).Format(time.RFC3339))
	for query, want := range map[string][]string{
		"":                          {"user.enabled", "user.disabled", "user.disabled"},
		"event=user.disabled":       {"user.disabled", "user.disabled"},
		"sub=BOB":                   {"user.enabled", "user.disabled"},
		"sub=RO":                    {"user.disabled", "user.disabled"}, // who did it
		"since=" + since:            {"user.enabled", "user.disabled"},
		"until=" + since:            {"user.disabled"},
		"limit=1":                   {"user.enabled"},
		"event=user.disabled&sub=X": nil,
	} {
		got := e.events(query)
		var events []string
		for _, ev := range got {
			events = append(events, ev.Event)
		}
		if len(events) != len(want) {
			t.Errorf("%q: %v, want %v", query, events, want)
			continue
		}
		for i := range want {
			if events[i] != want[i] {
				t.Errorf("%q: %v, want %v", query, events, want)
			}
		}
	}
	// Paging: before the oldest of the first page.
	first := e.events("limit=2")
	if rest := e.events("limit=2&before=" + strconv.FormatInt(first[1].ID, 10)); len(rest) != 1 || rest[0].Sub != "ALICE" {
		t.Errorf("second page: %+v", rest)
	}
}

func TestOverview(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil)
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO sessions (user_id, auth_time, amr) VALUES ('ALICE', now(), '{pwd}');
		INSERT INTO sessions (user_id, auth_time, amr, ended_at) VALUES ('ALICE', now() - interval '3 days', '{pwd}', now())`); err != nil {
		t.Fatal(err)
	}
	var o struct {
		Users, LoginsToday, LiveSessions, Applications, SendsLastDay, DailySendLimit int
	}
	if code := e.get(e.token(e.owner, nil), "/overview", &o); code != 200 ||
		o.Users != 2 || o.LoginsToday != 1 || o.LiveSessions != 1 || o.Applications != 2 || o.DailySendLimit != 1000 {
		t.Errorf("overview: %d %+v", code, o)
	}
}

// The writes that audit themselves.
func TestSelfAuditedWrites(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil)
	owner := e.token(e.owner, nil)
	var id string
	if err := e.pool.QueryRow(context.Background(),
		"INSERT INTO sessions (user_id, auth_time, amr) VALUES ('ALICE', now(), '{pwd}') RETURNING id").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/sessions/"+id, nil, nil); code != 204 {
		t.Fatalf("end session: %d", code)
	}
	if ev := e.audited("session.ended"); ev.Sub != "ALICE" || ev.Detail["session"] != id || ev.Detail["by"] != e.owner {
		t.Errorf("session.ended: %+v", ev)
	}

	if code := e.call("PUT", owner, "/users/ALICE/roles", map[string]any{"api": "urn:polaris:management-api", "roles": []string{"readonly"}}, nil); code != 204 {
		t.Fatalf("roles: %d", code)
	}
	if ev := e.audited("roles.assigned"); ev.Sub != "ALICE" || ev.Detail["by"] != e.owner {
		t.Errorf("roles.assigned: %+v", ev)
	}

	if code := e.call("PUT", owner, "/settings", settings{PasswordLogin: "on", DailySendLimit: 1, AuditRetentionDays: 1}, nil); code != 204 {
		t.Fatalf("settings: %d", code)
	}
	if ev := e.audited("settings.updated"); ev.Detail["by"] != e.owner {
		t.Errorf("settings.updated: %+v", ev)
	}
	if got := e.events(""); len(got) != 3 {
		t.Errorf("audited twice: %+v", got)
	}
}

// twoFactorOn gives sub a confirmed TOTP and a 恢复码.
func (e *env) twoFactorOn(sub string) {
	e.t.Helper()
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `INSERT INTO totp_credentials (user_id, secret, confirmed_at, last_step) VALUES ($1, 'x', now(), 0)`, sub); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO recovery_codes (user_id, mac) VALUES ($1, 'y')`, sub); err != nil {
		e.t.Fatal(err)
	}
}

func TestAdminResetsTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "username:alice")
	e.user("RO", []string{"readonly"})
	e.twoFactorOn("ALICE")
	app := e.session("ALICE", "polaris-console", false)
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)

	var detail struct{ TwoFactor bool }
	if code := e.get(ro, "/users/ALICE", &detail); code != 200 || !detail.TwoFactor {
		t.Fatalf("readonly sees 2FA on: %d %+v", code, detail)
	}
	if code := e.call("DELETE", ro, "/users/ALICE/2fa", nil, nil); code != 403 {
		t.Errorf("readonly resets: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/2fa", nil, nil); code != 204 {
		t.Fatalf("reset: %d", code)
	}
	if e.get(owner, "/users/ALICE", &detail); detail.TwoFactor {
		t.Error("2FA still on after reset")
	}
	var left int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM recovery_codes WHERE user_id = 'ALICE'`).Scan(&left); err != nil || left != 0 {
		t.Errorf("恢复码 left: %d %v", left, err)
	}
	// The User's Sessions live on.
	var list struct{ Sessions []session }
	if e.get(owner, "/users/ALICE/sessions", &list); len(list.Sessions) != 1 || list.Sessions[0].ID != app || !list.Sessions[0].Active {
		t.Errorf("Sessions after reset: %+v", list.Sessions)
	}
	if got := e.events(""); len(got) != 1 || got[0].Event != "mfa.reset" || got[0].Sub != "ALICE" || got[0].Detail["by"] != e.owner {
		t.Errorf("audit: %+v", got)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/2fa", nil, nil); code != 409 {
		t.Errorf("reset while off: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/NOBODY/2fa", nil, nil); code != 404 {
		t.Errorf("unknown User: %d", code)
	}
}

// pendingUser is a User an admin created: 待激活, with the initial password.
type pendingUser struct {
	Sub         string
	Pending     bool
	HasPassword bool
	Identifiers []struct{ Kind, Value string }
}

// createPending makes a User through the API, as the owner.
func (e *env) createPending(identifier, password string, out any) int {
	e.t.Helper()
	return e.call("POST", e.token(e.owner, nil), "/users",
		map[string]string{"identifier": identifier, "password": password}, out)
}

// 管理员创建 User (ADR 0016): 需要 users:write, 接受手机号 / 邮箱 / 用户名
// 任一标识符, 建出的 User 处于待激活并在管理 API 的读取里可见。
func TestAdminCreatesAPendingUser(t *testing.T) {
	e := start(t)
	e.trackAPI()
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)
	// 一条默认 Role, 用来验「照常获得业务 API 的默认 Role」.
	if code := e.call("PUT", e.token(e.owner, nil), "/apis/"+url.PathEscape(track), map[string]any{"name": "Track"}, nil); code != 204 {
		t.Fatalf("put API: %d", code)
	}
	if code := e.call("PUT", e.token(e.owner, nil), "/apis/"+url.PathEscape(track)+"/roles/member", map[string]any{"name": "会员", "permissions": []string{}, "default": true}, nil); code != 204 {
		t.Fatalf("default Role: %d", code)
	}
	var created pendingUser

	if code := e.call("POST", ro, "/users", map[string]string{"identifier": "nope@example.com", "password": "password1"}, nil); code != 403 {
		t.Errorf("readonly creates: %d", code)
	}
	if code := e.createPending("  Alice@Example.com ", "password1", &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	if created.Sub == "" || !created.Pending || !created.HasPassword ||
		len(created.Identifiers) != 1 || created.Identifiers[0].Value != "alice@example.com" {
		t.Errorf("created: %+v", created)
	}
	// 待激活在读取里可见: 列表和详情都有.
	var list struct{ Users []user }
	e.get(owner, "/users", &list)
	found := false
	for _, u := range list.Users {
		if u.Sub == created.Sub {
			found = true
			if !u.Pending {
				t.Errorf("the list does not show 待激活: %+v", u)
			}
		}
	}
	if !found {
		t.Error("the new User is not in the list")
	}
	var detail struct {
		Pending bool
		Roles   []role
	}
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 || !detail.Pending {
		t.Errorf("detail: %d %+v", code, detail)
	}
	// 照常获得业务 API 的默认 Role (rbac.md: 对所有创建途径一致).
	if !slices.ContainsFunc(detail.Roles, func(r role) bool { return r.API == track && r.Key == "member" }) {
		t.Errorf("no default Role: %+v", detail.Roles)
	}

	// 手机号与用户名同样接受, 各自归一化.
	for _, tc := range []struct{ in, kind, value string }{
		{"138 0000 2222", "phone", "+8613800002222"},
		{"Bob", "username", "bob"},
	} {
		var u pendingUser
		if code := e.createPending(tc.in, "password1", &u); code != 200 {
			t.Fatalf("%q: %d", tc.in, code)
		}
		if len(u.Identifiers) != 1 || u.Identifiers[0].Kind != tc.kind || u.Identifiers[0].Value != tc.value {
			t.Errorf("%q: %+v", tc.in, u.Identifiers)
		}
	}

	// 撞上已被占用的标识符: 明确错误, 而不是 500 或一个半成品账号.
	before := len(list.Users)
	for _, id := range []string{"alice@example.com", "13800002222", "bob"} {
		if code := e.createPending(id, "password1", nil); code != 409 {
			t.Errorf("%q: %d, want 409", id, code)
		}
	}
	e.get(owner, "/users", &list)
	if len(list.Users) != before+2 {
		t.Errorf("%d Users, want %d: a rejected create left a User behind", len(list.Users), before+3)
	}

	// 密码规则与标识符校验沿用现有.
	for name, body := range map[string]map[string]string{
		"short password":   {"identifier": "x@example.com", "password": "short"},
		"not a identifier": {"identifier": "not an identifier", "password": "password1"},
	} {
		if code := e.call("POST", owner, "/users", body, nil); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}

	// 审计: 每个新建的 User 一条 user.created, 操作人是管理员.
	if ev := e.audited("user.created"); ev.Detail["by"] != e.owner || ev.Detail["byType"] != "user" {
		t.Errorf("audit: %+v", ev)
	}
	mine := e.events("event=user.created&sub=" + created.Sub)
	if len(mine) != 1 || mine[0].Detail["by"] != e.owner || mine[0].Detail["byType"] != "user" {
		t.Errorf("the first User's audit: %+v", mine)
	}
	// 每个新建的 User 一条 user.created, 而且只此一条: 自审的那条不再走
	// 通用审计, 否则每次创建会记两条.
	if got := e.events("event=user.created"); len(got) != 3 {
		t.Errorf("%d user.created events, want 3: %+v", len(got), got)
	}
	if got := e.events("event=create-user"); len(got) != 0 {
		t.Errorf("the generic audit fired too: %+v", got)
	}
}

// 待激活可按状态筛选, 禁用优先: 禁用中的待激活 User 落进 active 一侧。
func TestUserListFiltersByStatus(t *testing.T) {
	e := start(t)
	e.user("ACTIVE", nil, "email:active@example.com")
	var p1, p2 pendingUser
	e.createPending("p1@example.com", "password1", &p1)
	e.createPending("p2@example.com", "password1", &p2)
	if code := e.call("POST", e.token(e.owner, nil), "/users/"+p2.Sub+"/disable", nil, nil); code != 204 {
		t.Fatalf("disable: %d", code)
	}
	owner := e.token(e.owner, nil)

	var list struct{ Users []user }
	for query, want := range map[string][]string{
		"":                {"ACTIVE", p1.Sub, p2.Sub, e.owner},
		"?status=pending": {p1.Sub},
		"?status=active":  {"ACTIVE", p2.Sub, e.owner},
	} {
		want := slices.Clone(want)
		slices.Sort(want)
		if code := e.get(owner, "/users"+query, &list); code != 200 || !slices.Equal(subs(list.Users), want) {
			t.Errorf("users%s: %d %v, want %v", query, code, subs(list.Users), want)
		}
	}
	if code := e.get(owner, "/users?status=nonsense", &list); code != 422 {
		t.Errorf("unknown status: %d", code)
	}
}

// 密码登录关闭时创建端点返回 422, 文案说明原因 (ADR 0017: 它是这一包功能的
// 前置条件 —— 初始密码与邀请都要走密码).
func TestCreateUserNeedsPasswordLogin(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	// 所有者先给自己一条密码之外的途径, 否则保存「关闭」会被自锁守卫拒绝.
	if code := e.call("PUT", owner, "/users/"+e.owner+"/identifiers/email", map[string]string{"value": "owner@example.com"}, nil); code != 204 {
		t.Fatalf("bind email: %d", code)
	}
	if code := e.call("PUT", owner, "/settings", settings{PasswordLogin: "off", DailySendLimit: 1000, AuditRetentionDays: 180}, nil); code != 204 {
		t.Fatalf("turn password login off: %d", code)
	}
	var out struct{ Detail string }
	if code := e.call("POST", owner, "/users", map[string]string{"identifier": "new@example.com", "password": "password1"}, &out); code != 422 {
		t.Fatalf("create with password login off: %d", code)
	}
	if !strings.Contains(out.Detail, "密码登录") {
		t.Errorf("the message does not say why: %q", out.Detail)
	}
	var list struct{ Users []user }
	e.get(owner, "/users", &list)
	if len(list.Users) != 1 {
		t.Errorf("%d Users, want 1: the create went through anyway", len(list.Users))
	}
}

// 部署脚本与业务后端以 M2M Application 的身份开号 (ADR 0015 + 0016):
// 审计的操作人是那个 Application, 不是某个 User。
func TestM2MApplicationCreatesAUser(t *testing.T) {
	e := start(t)
	e.trackAPI()
	app := e.m2mApp(identity.ManagementAPI, "admin")
	var created pendingUser
	if code := e.call("POST", e.token(app, nil), "/users", map[string]string{"identifier": "new@example.com", "password": "password1"}, &created); code != 200 {
		t.Fatalf("an M2M Application creates: %d", code)
	}
	if !created.Pending {
		t.Errorf("not 待激活: %+v", created)
	}
	if ev := e.audited("user.created"); ev.Detail["by"] != app || ev.Detail["byType"] != "application" {
		t.Errorf("audit: %+v", ev)
	}
}
