package management_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/stars-auth/internal/crypt"
	"github.com/zibyn/stars-auth/internal/db"
	"github.com/zibyn/stars-auth/internal/db/dbtest"
	"github.com/zibyn/stars-auth/internal/db/sqlc"
	"github.com/zibyn/stars-auth/internal/identity"
	"github.com/zibyn/stars-auth/internal/login"
	"github.com/zibyn/stars-auth/internal/management"
	"github.com/zibyn/stars-auth/internal/oidcstore"
	"github.com/zibyn/stars-auth/internal/server"
)

type env struct {
	t      *testing.T
	pool   *pgxpool.Pool
	issuer string
	keys   *oidcstore.Keys
	owner  string // sub
}

func start(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	keys := oidcstore.NewKeys(pool, keyring)
	if err := keys.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	ids := identity.New(pool, keyring)
	token, err := ids.SetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ids.Bootstrap(ctx, token, "owner", "password1")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	// A Passkey's RP ID is the issuer's hostname, which may not be an IP
	// address; the test server is reached at localhost.
	issuer := "http://localhost:" + strconv.Itoa(ts.Listener.Addr().(*net.TCPAddr).Port)
	svc, err := management.New(pool, keyring, issuer)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = server.New(pool.Ping, http.NotFoundHandler(), nil, svc.Register)
	return &env{t: t, pool: pool, issuer: issuer, keys: keys, owner: owner}
}

// user adds a User with the given Identifiers ("kind:value") and Management
// API Roles.
func (e *env) user(sub string, roles []string, idents ...string) {
	e.t.Helper()
	ctx := context.Background()
	q := sqlc.New(e.pool)
	if err := q.CreateUser(ctx, sub); err != nil {
		e.t.Fatal(err)
	}
	for _, id := range idents {
		kind, value, _ := strings.Cut(id, ":")
		if err := q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: kind, Value: value}); err != nil {
			e.t.Fatal(err)
		}
	}
	for _, r := range roles {
		if err := q.AssignRole(ctx, sqlc.AssignRoleParams{UserID: sub, Api: identity.ManagementAPI, Role: r}); err != nil {
			e.t.Fatal(err)
		}
	}
}

// m2mApp adds an M2M Application whose default API is api, holding roles on
// it, and returns its client_id — the sub of its client_credentials token.
func (e *env) m2mApp(api string, roles ...string) string {
	e.t.Helper()
	var created struct{ Application application }
	owner := e.token(e.owner, nil)
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "m2m", "settings": m2mSettings(api)}, &created); code != 200 {
		e.t.Fatalf("create an m2m Application: %d", code)
	}
	if code := e.call("PUT", owner, "/applications/"+created.Application.ClientID+"/roles", map[string]any{"roles": append([]string{}, roles...)}, nil); code != 204 {
		e.t.Fatalf("assign Roles to an m2m Application: %d", code)
	}
	return created.Application.ClientID
}

// token signs an access token the way the OIDC provider does, with the
// current signing key; edit tweaks the claims and header type.
func (e *env) token(sub string, edit func(claims map[string]any, typ *string)) string {
	e.t.Helper()
	jwks, err := e.keys.JWKS(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	claims := map[string]any{
		"iss": e.issuer, "sub": sub, "aud": identity.ManagementAPI, "client_id": login.ConsoleClientID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	typ := "at+jwt"
	if edit != nil {
		edit(claims, &typ)
	}
	k := jwks.Keys[0]
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k.Key, KeyID: k.KeyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		e.t.Fatal(err)
	}
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return signed
}

// get calls the Management API with a bearer token ("" for none) and decodes
// a 200 body into out.
func (e *env) get(token, path string, out any) int {
	e.t.Helper()
	return e.call("GET", token, path, nil, out)
}

// call sends in as a JSON body (when not nil) and decodes a 200 body into out.
func (e *env) call(method, token, path string, in, out any) int {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.issuer+management.Prefix+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	// A 422 carries its explanation in the problem document's detail field;
	// callers decode it by asking for a struct with one.
	if out != nil && (resp.StatusCode == 200 || resp.StatusCode == 422) {
		if err := json.Unmarshal(raw, out); err != nil && resp.StatusCode == 200 {
			e.t.Fatalf("%s: %v\n%s", path, err, raw)
		}
	}
	return resp.StatusCode
}

type role struct{ API, Key, Name string }

type user struct {
	Sub         string
	Pending     bool
	Identifiers []struct{ Kind, Value string }
	Roles       []role
	HasPassword bool
}

func subs(users []user) []string {
	var s []string
	for _, u := range users {
		s = append(s, u.Sub)
	}
	slices.Sort(s)
	return s
}

func TestOwnerBrowsesUsers(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "phone:+8613800001111", "email:alice@example.com")
	e.user("BOB", []string{"readonly"}, "email:bob@example.com", "username:bobby")
	tok := e.token(e.owner, nil)

	var me struct {
		Sub         string
		Identifier  string
		Permissions []string
	}
	if code := e.get(tok, "/me", &me); code != 200 || me.Sub != e.owner || me.Identifier != "owner" ||
		!slices.Contains(me.Permissions, "users:read") || !slices.Contains(me.Permissions, "keys:rotate") {
		t.Errorf("me: %d %+v", code, me)
	}
	// The primary Identifier: phone, then email, then username.
	if code := e.get(e.token("BOB", nil), "/me", &me); code != 200 || me.Identifier != "bob@example.com" {
		t.Errorf("me as BOB: %d %+v", code, me)
	}

	var list struct{ Users []user }
	for query, want := range map[string][]string{
		"":                               {"ALICE", "BOB", e.owner},
		"?q=13800001111":                 {"ALICE"},
		"?q=Alice@Example":               {"ALICE"},
		"?q=bobby":                       {"BOB"},
		"?q=" + strings.ToLower(e.owner): {e.owner},
		"?q=nobody":                      nil,
		"?role=owner":                    {e.owner},
		"?role=readonly&q=bob":           {"BOB"},
		"?role=admin":                    nil,
		"?api=x&role=owner":              nil,
	} {
		want := slices.Clone(want)
		slices.Sort(want)
		list.Users = nil
		if code := e.get(tok, "/users"+query, &list); code != 200 || !slices.Equal(subs(list.Users), want) {
			t.Errorf("users%s: %d %v, want %v", query, code, subs(list.Users), want)
		}
	}

	// The Roles column.
	e.get(tok, "/users?q=bobby", &list)
	if len(list.Users) != 1 || !slices.Equal(list.Users[0].Roles, []role{{identity.ManagementAPI, "readonly", "只读"}}) {
		t.Errorf("bob's roles: %+v", list.Users)
	}

	var detail user
	if code := e.get(tok, "/users/ALICE", &detail); code != 200 || len(detail.Identifiers) != 2 || detail.HasPassword || len(detail.Roles) != 0 {
		t.Errorf("alice: %d %+v", code, detail)
	}
	if code := e.get(tok, "/users/"+e.owner, &detail); code != 200 || !detail.HasPassword ||
		!slices.Equal(detail.Roles, []role{{identity.ManagementAPI, "owner", "所有者"}}) {
		t.Errorf("owner: %d %+v", code, detail)
	}
	if code := e.get(tok, "/users/NOPE", nil); code != 404 {
		t.Errorf("unknown user: %d", code)
	}

	var roles struct{ Roles []role }
	if code := e.get(tok, "/roles", &roles); code != 200 || len(roles.Roles) != 3 {
		t.Errorf("roles: %d %+v", code, roles)
	}
}

func TestOnlyAdminsWithValidTokens(t *testing.T) {
	e := start(t)
	e.user("CAROL", []string{"readonly"})
	e.user("DAVE", nil)

	for name, tok := range map[string]string{
		"no token":    "",
		"garbage":     "not-a-jwt",
		"wrong aud":   e.token(e.owner, func(c map[string]any, _ *string) { c["aud"] = "https://api.example" }),
		"wrong iss":   e.token(e.owner, func(c map[string]any, _ *string) { c["iss"] = "https://evil.example" }),
		"expired":     e.token(e.owner, func(c map[string]any, _ *string) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"an ID token": e.token(e.owner, func(_ map[string]any, typ *string) { *typ = "JWT" }),
	} {
		if code := e.get(tok, "/users", nil); code != 401 {
			t.Errorf("%s: %d, want 401", name, code)
		}
	}

	if code := e.get(e.token("DAVE", nil), "/users", nil); code != 403 {
		t.Errorf("non-admin: %d, want 403", code)
	}

	// Any Management API Role makes an admin, even one with no Permissions.
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO roles (api, key, name) VALUES ('urn:stars-auth:management-api', 'empty', 'Empty');
		INSERT INTO user_roles VALUES ('DAVE', 'urn:stars-auth:management-api', 'empty')`); err != nil {
		t.Fatal(err)
	}
	dave := e.token("DAVE", nil)
	if code := e.get(dave, "/me", nil); code != 200 {
		t.Errorf("admin without Permissions, /me: %d, want 200", code)
	}
	if code := e.get(dave, "/users", nil); code != 403 {
		t.Errorf("admin without users:read: %d, want 403", code)
	}

	// Roles are read on every request: taking CAROL's away locks her out at
	// once, with the same token.
	carol := e.token("CAROL", nil)
	if code := e.get(carol, "/users", nil); code != 200 {
		t.Fatalf("readonly admin: %d", code)
	}
	if _, err := e.pool.Exec(context.Background(), "DELETE FROM user_roles WHERE user_id = 'CAROL'"); err != nil {
		t.Fatal(err)
	}
	if code := e.get(carol, "/users", nil); code != 403 {
		t.Errorf("after losing her Role: %d, want 403", code)
	}
}

// An M2M Application calls the Management API as itself: its token's sub is
// its client_id, and the Management API takes it as the caller, authorized
// live on the Management API Roles the Application holds (ADR 0015).
func TestM2MCallsManagementAPI(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	reader := e.m2mApp(identity.ManagementAPI, "readonly")
	tok := e.token(reader, nil)

	// Its Roles are readonly's: users:read, but no users:write.
	if code := e.get(tok, "/users", nil); code != 200 {
		t.Errorf("an M2M Application reading Users: %d, want 200", code)
	}
	if code := e.call("POST", tok, "/users/RO/disable", nil, nil); code != 403 {
		t.Errorf("an M2M Application without users:write: %d, want 403", code)
	}
	var me struct {
		Sub         string
		Identifier  string
		Permissions []string
	}
	if code := e.get(tok, "/me", &me); code != 200 || me.Sub != reader || me.Identifier != "" || !slices.Contains(me.Permissions, "users:read") {
		t.Errorf("me as an M2M Application: %d %+v", code, me)
	}
	// Holding no Role is no admin, exactly as for a User.
	if code := e.get(e.token(e.m2mApp(identity.ManagementAPI), nil), "/users", nil); code != 403 {
		t.Errorf("an M2M Application holding no Role: %d, want 403", code)
	}

	// Its Roles are read on every request: taking them away closes it out at
	// once, with the same token.
	owner := e.token(e.owner, nil)
	if code := e.call("PUT", owner, "/applications/"+reader+"/roles", map[string]any{"roles": []string{}}, nil); code != 204 {
		t.Fatalf("take its Roles away: %d", code)
	}
	if code := e.get(tok, "/users", nil); code != 403 {
		t.Errorf("after losing its Role: %d, want 403", code)
	}
	// Deleting the Application rejects its token at once too, whatever Roles
	// it held.
	gone := e.m2mApp(identity.ManagementAPI, "readonly")
	goneTok := e.token(gone, nil)
	if code := e.get(goneTok, "/users", nil); code != 200 {
		t.Fatalf("a fresh M2M Application: %d", code)
	}
	if code := e.call("DELETE", owner, "/applications/"+gone, nil, nil); code != 204 {
		t.Fatalf("delete an m2m Application: %d", code)
	}
	if code := e.get(goneTok, "/users", nil); code != 403 {
		t.Errorf("after deleting the Application: %d, want 403", code)
	}

	// An M2M Application is never an owner, so holding a Management API Role
	// does not stand in for the last one: the guard counts Users only.
	e.m2mApp(identity.ManagementAPI, "readonly")
	if code := e.call("PUT", owner, "/users/"+e.owner+"/roles", map[string]any{"api": identity.ManagementAPI, "roles": []string{"admin"}}, nil); code != 409 {
		t.Errorf("the last owner steps down while an M2M Application holds a Management API Role: %d, want 409", code)
	}

	// 管理员必须启用两步验证或 Passkey turns an admin away; not an M2M
	// Application, which has no one to turn 两步验证 on for it.
	e.user("CAROL", []string{"readonly"})
	e.twoFactorOn(e.owner)
	policy := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, AdminsNeedTwoFactor: true, PasskeyLogin: true}
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("turn on 管理员必须启用两步验证: %d", code)
	}
	if code, err := e.problem(e.token("CAROL", nil), "/users"); code != 403 || err != management.TwoFactorRequired {
		t.Errorf("an admin without 两步验证: %d %q, want 403 %s", code, err, management.TwoFactorRequired)
	}
	if code := e.get(e.token(e.m2mApp(identity.ManagementAPI, "readonly"), nil), "/users", nil); code != 200 {
		t.Errorf("an M2M Application under 管理员必须启用两步验证: %d, want 200", code)
	}
}

func TestOpenAPIDocument(t *testing.T) {
	e := start(t)
	var doc struct {
		Paths map[string]any
	}
	if code := e.get("", "/openapi.json", &doc); code != 200 || doc.Paths["/users"] == nil || doc.Paths["/users/{sub}"] == nil {
		t.Errorf("openapi: %d %v", code, doc.Paths)
	}
}
