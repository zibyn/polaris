package account_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/account"
	"github.com/zibyn/polaris/internal/channel"
	_ "github.com/zibyn/polaris/internal/channel/webhook"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/login"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/apple/appletest"
	"github.com/zibyn/polaris/internal/server"
	"github.com/zibyn/polaris/internal/webhook"
)

type env struct {
	t       *testing.T
	pool    *pgxpool.Pool
	keyring *crypt.Keyring
	issuer  string
	keys    *oidcstore.Keys
	inbox   *inbox
	// cookies maps signIn's access tokens to their Session's cookie.
	cookies map[string]string
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
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	// A Passkey's RP ID is the issuer's hostname, which may not be an IP
	// address; the test server is reached at localhost.
	issuer := "http://localhost:" + strconv.Itoa(ts.Listener.Addr().(*net.TCPAddr).Port)
	auth, err := login.New(ctx, pool, keyring, issuer) // Providers come back to its callback
	if err != nil {
		t.Fatal(err)
	}
	accountSvc, err := account.New(pool, keyring, issuer)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = server.New(pool.Ping, http.NotFoundHandler(), nil, auth.Register, accountSvc.Register)
	e := &env{t: t, pool: pool, keyring: keyring, issuer: issuer, keys: keys, inbox: &inbox{codes: map[string]string{}}, cookies: map[string]string{}}
	hook := httptest.NewServer(e.inbox)
	t.Cleanup(hook.Close)
	for _, kind := range []string{"phone", "email"} {
		if err := channel.NewStore(pool, keyring).Put(ctx, kind, "webhook", map[string]string{"url": hook.URL, "secret": "s"}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// inbox is the Webhook Channel's receiver: the last code sent to each
// Identifier.
type inbox struct {
	mu    sync.Mutex
	codes map[string]string
}

func (in *inbox) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	var m struct{ To, Code string }
	_ = json.NewDecoder(r.Body).Decode(&m)
	in.mu.Lock()
	defer in.mu.Unlock()
	in.codes[m.To] = m.Code
}

func (in *inbox) take(to string) string {
	in.mu.Lock()
	defer in.mu.Unlock()
	code := in.codes[to]
	delete(in.codes, to)
	return code
}

// user adds a User with the given Identifiers ("kind:value").
func (e *env) user(sub string, idents ...string) {
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
}

// signIn starts a browser Session for sub, authenticated ago, and returns
// an account center access token issued in it.
func (e *env) signIn(sub string, ago time.Duration) string {
	e.t.Helper()
	var sid string
	cookie := rand.Text()
	idHash := sha256.Sum256([]byte(cookie))
	if err := e.pool.QueryRow(context.Background(), `
		INSERT INTO sessions (id_hash, client_id, user_id, auth_time, amr)
		VALUES ($3, 'polaris-account', $1, now() - $2 * interval '1 second', '{sms}') RETURNING id`,
		sub, ago.Seconds(), idHash[:]).Scan(&sid); err != nil {
		e.t.Fatal(err)
	}
	tok := e.token(sub, map[string]any{"sid": sid})
	e.cookies[tok] = cookie
	return tok
}

// token signs an access token the way the OIDC provider does; extra adds
// or overrides claims.
func (e *env) token(sub string, extra map[string]any) string {
	e.t.Helper()
	jwks, err := e.keys.JWKS(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	claims := map[string]any{
		"iss": e.issuer, "sub": sub, "aud": identity.AccountAPI, "client_id": login.AccountClientID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	k := jwks.Keys[0]
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k.Key, KeyID: k.KeyID}},
		(&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		e.t.Fatal(err)
	}
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return signed
}

// call sends body as JSON (nil for none) with a bearer token and decodes a
// 2xx body into out; it returns the status.
func (e *env) call(method, token, path string, body, out any) int {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		js, _ := json.Marshal(body)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, e.issuer+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: %v %s", method, path, err, raw)
		}
	}
	return resp.StatusCode
}

type me struct {
	RecentAuthUntil time.Time `json:"recentAuthUntil"`
	Sub             string    `json:"sub"`
	Identifiers     []struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"identifiers"`
	HasPassword bool `json:"hasPassword"`
}

// The Account API takes the account center's access tokens, while the
// Session they were issued in lives.
func TestAccountAPINeedsALiveSession(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)

	var got me
	if code := e.call("GET", tok, "/v1/account/me", nil, &got); code != 200 ||
		got.Sub != "ALICE" || len(got.Identifiers) != 1 || got.Identifiers[0].Value != "+8613800138000" {
		t.Fatalf("me: %d %+v", code, got)
	}
	if code := e.call("GET", e.token("ALICE", map[string]any{"aud": identity.ManagementAPI}), "/v1/account/me", nil, nil); code != 401 {
		t.Errorf("another API's token: %d", code)
	}
	if code := e.call("GET", e.token("ALICE", nil), "/v1/account/me", nil, nil); code != 401 {
		t.Errorf("token without a Session: %d", code)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE sessions SET ended_at = now()"); err != nil {
		t.Fatal(err)
	}
	if code := e.call("GET", tok, "/v1/account/me", nil, nil); code != 401 {
		t.Errorf("ended Session: %d", code)
	}
}

// Sensitive actions need an authentication in the last 10 minutes; a code
// to one of the User's own Identifiers, or their password, makes one.
func TestReauthentication(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000", "email:alice@example.com")
	tok := e.signIn("ALICE", 20*time.Minute)

	if code := e.call("DELETE", tok, "/v1/account/identifiers/email", nil, nil); code != 403 {
		t.Fatalf("unbind without reauthentication: %d", code)
	}
	if code := e.call("POST", tok, "/v1/account/reauth/code", map[string]string{"kind": "phone"}, nil); code != 204 {
		t.Fatalf("send reauth code: %d", code)
	}
	code := e.inbox.take("+8613800138000")
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "phone", "code": "000000x"}, nil); c != 422 {
		t.Errorf("wrong code: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "phone", "code": code}, nil); c != 204 {
		t.Fatalf("reauth: %d", c)
	}
	var got me
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 || time.Until(got.RecentAuthUntil) < 9*time.Minute {
		t.Errorf("after reauth: %d %+v", c, got)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/email", nil, nil); c != 204 {
		t.Errorf("unbind after reauthentication: %d", c)
	}

	// A password works too, when the setting lets this User use one.
	e.password("ALICE", "password1")
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'on'; UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"password": "wrong-one"}, nil); c != 422 {
		t.Errorf("wrong password: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"password": "password1"}, nil); c != 204 {
		t.Errorf("reauth by password: %d", c)
	}
}

// password sets sub's password.
func (e *env) password(sub, password string) {
	e.t.Helper()
	if err := identity.New(e.pool, e.keyring).SetPassword(context.Background(), sub, password); err != nil {
		e.t.Fatal(err)
	}
}

// A new phone number or email is verified with a code; the old one is not
// asked for. One another User holds cannot be bound.
func TestChangeIdentifier(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "email:bob@example.com")
	tok := e.signIn("ALICE", 0)

	if c := e.call("POST", tok, "/v1/account/identifiers/phone/code", map[string]string{"value": "13900139000"}, nil); c != 204 {
		t.Fatalf("send code to the new phone: %d", c)
	}
	code := e.inbox.take("+8613900139000")
	if c := e.call("PUT", tok, "/v1/account/identifiers/phone", map[string]string{"value": "13900139000", "code": "nope"}, nil); c != 422 {
		t.Errorf("wrong code: %d", c)
	}
	if c := e.call("PUT", tok, "/v1/account/identifiers/phone", map[string]string{"value": "13900139000", "code": code}, nil); c != 204 {
		t.Fatalf("change phone: %d", c)
	}
	// Binding an email the User has none of works the same way.
	if c := e.call("POST", tok, "/v1/account/identifiers/email/code", map[string]string{"value": "Alice@Example.com"}, nil); c != 204 {
		t.Fatalf("send code to the new email: %d", c)
	}
	if c := e.call("PUT", tok, "/v1/account/identifiers/email", map[string]string{"value": "alice@example.com", "code": e.inbox.take("alice@example.com")}, nil); c != 204 {
		t.Fatalf("bind email: %d", c)
	}
	var got me
	e.call("GET", tok, "/v1/account/me", nil, &got)
	if len(got.Identifiers) != 2 || got.Identifiers[0].Value != "alice@example.com" || got.Identifiers[1].Value != "+8613900139000" {
		t.Errorf("identifiers: %+v", got.Identifiers)
	}

	if c := e.call("POST", tok, "/v1/account/identifiers/email/code", map[string]string{"value": "13900139000"}, nil); c != 422 {
		t.Errorf("a phone number as the email: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/identifiers/email/code", map[string]string{"value": "bob@example.com"}, nil); c != 409 {
		t.Errorf("another User's email: %d", c)
	}
}

// Password managers send a User whose saved password is weak or leaked to
// /.well-known/change-password, which lands them in the account center's
// 安全 section. With password login off there is nothing to change, so it is
// not served (docs/spec/authentication.md「密码管理器适配」).
func TestChangePasswordWellKnown(t *testing.T) {
	e := start(t)
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	fetch := func() (int, string) {
		t.Helper()
		resp, err := noRedirect.Get(e.issuer + "/.well-known/change-password")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close() //nolint:errcheck
		return resp.StatusCode, resp.Header.Get("Location")
	}
	// Password login is on by default, so the file is there.
	if code, loc := fetch(); code != 302 || loc != e.issuer+"/account#passkeys" {
		t.Errorf("change-password while on: %d %q", code, loc)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'off'"); err != nil {
		t.Fatal(err)
	}
	if code, _ := fetch(); code != 404 {
		t.Errorf("change-password while off: %d, want 404", code)
	}
}

// The last way to sign in cannot be removed: a phone number, an email, or a
// username with a password.
func TestLastLoginPathStays(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000", "username:alice")
	tok := e.signIn("ALICE", 0)

	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 422 {
		t.Errorf("unbind the only phone, username without password: %d", c)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'on'"); err != nil {
		t.Fatal(err)
	}
	if c := e.call("PUT", tok, "/v1/account/password", map[string]string{"password": "short"}, nil); c != 422 {
		t.Errorf("too short a password: %d", c)
	}
	if c := e.call("PUT", tok, "/v1/account/password", map[string]string{"password": "password1"}, nil); c != 204 {
		t.Fatalf("set password: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("unbind phone, username and password stay: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/password", nil, nil); c != 422 {
		t.Errorf("remove the password of the last login path: %d", c)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_log WHERE sub = 'ALICE' AND event IN ('password.changed', 'identifier.removed') AND detail->>'by' = 'ALICE'").Scan(&n); err != nil || n != 2 {
		t.Errorf("audited %d events: %v", n, err)
	}

	// With password login off, no password can be set.
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'off'"); err != nil {
		t.Fatal(err)
	}
	if c := e.call("PUT", tok, "/v1/account/password", map[string]string{"password": "password2"}, nil); c != 422 {
		t.Errorf("set password while password login is off: %d", c)
	}
}

// A User sees their Sessions, ended ones too, and can sign any of them out.
func TestOwnSessions(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "phone:+8613900139000")
	tok := e.signIn("ALICE", 0)
	other := e.signIn("ALICE", time.Hour)
	e.signIn("BOB", 0)

	type session struct {
		ID          string `json:"id"`
		Application string `json:"application"`
		Current     bool   `json:"current"`
		Active      bool   `json:"active"`
	}
	var list struct{ Sessions []session }
	if c := e.call("GET", tok, "/v1/account/sessions", nil, &list); c != 200 || len(list.Sessions) != 2 {
		t.Fatalf("list: %d %+v", c, list)
	}
	var current, rest session
	for _, s := range list.Sessions {
		if s.Current {
			current = s
		} else {
			rest = s
		}
	}
	if current.ID == "" || rest.ID == "" || current.Application != "Polaris 账号中心" {
		t.Fatalf("sessions: %+v", list.Sessions)
	}
	var bob string
	if err := e.pool.QueryRow(context.Background(), "SELECT id FROM sessions WHERE user_id = 'BOB'").Scan(&bob); err != nil {
		t.Fatal(err)
	}
	if c := e.call("DELETE", tok, "/v1/account/sessions/"+bob, nil, nil); c != 404 {
		t.Errorf("end another User's Session: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/sessions/"+rest.ID, nil, nil); c != 204 {
		t.Fatalf("end Session: %d", c)
	}
	if c := e.call("GET", other, "/v1/account/me", nil, nil); c != 401 {
		t.Errorf("the ended Session's token: %d", c)
	}
	e.call("GET", tok, "/v1/account/sessions", nil, &list)
	if len(list.Sessions) != 2 {
		t.Errorf("ended Session left the list: %+v", list.Sessions)
	}
	for _, s := range list.Sessions {
		if s.ID == rest.ID && s.Active {
			t.Errorf("ended Session still active: %+v", s)
		}
	}
}

// Exporting gives the User's data as JSON, after reauthenticating.
func TestExport(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO consents (user_id, version, client_id) VALUES ('ALICE', 'v1', 'rp');
		INSERT INTO audit_log (event, sub, detail) VALUES ('identifier.replaced', 'ALICE', '{"kind": "phone", "by": "ADMIN"}');
		INSERT INTO audit_log (event, sub, detail) VALUES ('user.disabled', 'BOB', '{"by": "ADMIN"}')`); err != nil {
		t.Fatal(err)
	}
	if c := e.call("GET", e.signIn("ALICE", time.Hour), "/v1/account/export", nil, nil); c != 403 {
		t.Errorf("export without reauthentication: %d", c)
	}
	var got struct {
		Sub         string           `json:"sub"`
		Identifiers []map[string]any `json:"identifiers"`
		Credentials struct {
			Password bool `json:"password"`
		} `json:"credentials"`
		Sessions []map[string]any `json:"sessions"`
		Consents []struct {
			Version string `json:"version"`
		} `json:"consents"`
		AuditEvents []struct {
			Event string `json:"event"`
		} `json:"auditEvents"`
	}
	if c := e.call("GET", e.signIn("ALICE", 0), "/v1/account/export", nil, &got); c != 200 {
		t.Fatalf("export: %d", c)
	}
	if got.Sub != "ALICE" || len(got.Identifiers) != 1 || got.Credentials.Password || len(got.Sessions) != 2 ||
		len(got.Consents) != 1 || got.Consents[0].Version != "v1" || len(got.AuditEvents) != 1 || got.AuditEvents[0].Event != "identifier.replaced" {
		t.Errorf("export: %+v", got)
	}
}

// receiver is an Application's webhook endpoint, checking signatures the
// Standard Webhooks way.
type receiver struct {
	t      *testing.T
	secret string
	mu     sync.Mutex
	events []map[string]any
	fail   int // answer 500 this many times first
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	id, ts := r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp")
	mac := hmac.New(sha256.New, []byte(rc.secret))
	mac.Write([]byte(id + "." + ts + "." + string(body)))
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if id == "" || r.Header.Get("webhook-signature") != want {
		rc.t.Errorf("bad signature: id %q ts %q sig %q", id, ts, r.Header.Get("webhook-signature"))
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.fail > 0 {
		rc.fail--
		w.WriteHeader(500)
		return
	}
	var ev map[string]any
	_ = json.Unmarshal(body, &ev)
	rc.events = append(rc.events, ev)
}

// webhookApp registers an Application whose webhook goes to rc.
func (e *env) webhookApp(clientID string, rc *receiver) {
	e.t.Helper()
	ctx := context.Background()
	if err := oidcstore.CreateApplication(ctx, e.pool, oidcstore.Application{ClientID: clientID, Name: clientID}); err != nil {
		e.t.Fatal(err)
	}
	sealed, err := e.keyring.Seal([]byte(rc.secret), []byte("application:"+clientID+":webhook"))
	if err != nil {
		e.t.Fatal(err)
	}
	srv := httptest.NewServer(rc)
	e.t.Cleanup(srv.Close)
	if _, err := e.pool.Exec(ctx, "UPDATE applications SET webhook_url = $2, webhook_secret = $3 WHERE client_id = $1", clientID, srv.URL, sealed); err != nil {
		e.t.Fatal(err)
	}
}

// Deleting an account takes effect at once: the sub is gone for good, the
// phone number is free for a new User, and every Application with a webhook
// hears of it.
func TestDeleteAccount(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	const phone = "+8613800138000"
	ids := identity.New(e.pool, e.keyring)
	sub, err := ids.SignIn(ctx, "phone", phone)
	if err != nil {
		t.Fatal(err)
	}
	rc := &receiver{t: t, secret: "s3cret", fail: 1}
	e.webhookApp("rp", rc)
	tok := e.signIn(sub, 0)
	other := e.signIn(sub, 0)

	if c := e.call("DELETE", e.signIn(sub, time.Hour), "/v1/account/me", nil, nil); c != 403 {
		t.Errorf("delete without reauthentication: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/me", nil, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c := e.call("GET", other, "/v1/account/me", nil, nil); c != 401 {
		t.Errorf("another Session of the deleted User: %d", c)
	}
	again, err := ids.SignIn(ctx, "phone", phone)
	if err != nil || again == sub {
		t.Errorf("same phone signs in again as %q (was %q): %v", again, sub, err)
	}

	hooks := webhook.New(e.pool, e.keyring, "https://auth.example")
	if err := hooks.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rc.events) != 0 {
		t.Fatalf("delivered despite a 500: %v", rc.events)
	}
	// The failed delivery is retried later.
	if _, err := e.pool.Exec(ctx, "UPDATE webhook_deliveries SET next_at = now()"); err != nil {
		t.Fatal(err)
	}
	if err := hooks.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rc.events) != 1 || rc.events[0]["type"] != "user.deleted" || rc.events[0]["data"].(map[string]any)["sub"] != sub {
		t.Errorf("events: %v", rc.events)
	}
	var left int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM webhook_deliveries").Scan(&left); err != nil || left != 0 {
		t.Errorf("%d deliveries left: %v", left, err)
	}
}

// The last owner cannot delete their account.
func TestLastOwnerCannotDeleteThemselves(t *testing.T) {
	e := start(t)
	e.user("OWNER", "username:owner")
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO user_roles VALUES ('OWNER', $1, 'owner')", identity.ManagementAPI); err != nil {
		t.Fatal(err)
	}
	if c := e.call("DELETE", e.signIn("OWNER", 0), "/v1/account/me", nil, nil); c != 409 {
		t.Errorf("last owner deletes themselves: %d", c)
	}
}

// Apps delete the account through the direct auth API with their own access
// token, after a fresh sign-in; otherwise they are told to step up
// (RFC 9470).
func TestDirectAPIDeletesTheAccount(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	del := func(token string) *http.Response {
		req, _ := http.NewRequest("POST", e.issuer+"/v1/auth/delete", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	appToken := func(ago time.Duration) string {
		tok := e.signIn("ALICE", ago)
		claims, _ := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
		var c map[string]any
		_ = claims.UnsafeClaimsWithoutVerification(&c)
		return e.token("ALICE", map[string]any{"sid": c["sid"], "aud": "https://track.example", "client_id": "app"})
	}

	if resp := del("garbage"); resp.StatusCode != 401 {
		t.Errorf("bad token: %d", resp.StatusCode)
	}
	resp := del(appToken(time.Hour))
	if www := resp.Header.Get("WWW-Authenticate"); resp.StatusCode != 401 ||
		!strings.Contains(www, `error="insufficient_user_authentication"`) || !strings.Contains(www, `max_age="600"`) {
		t.Errorf("stale sign-in: %d %q", resp.StatusCode, www)
	}
	if resp := del(appToken(0)); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d users left: %v", n, err)
	}
}

// totp is the code an authenticator shows for a Base32 secret at t
// (RFC 6238: SHA1, 6 digits, 30 seconds).
func totp(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, at.Unix()/30)
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[sum[19]&0xf:]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

type twoFactor struct {
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabledAt"`
	RecoveryCodesLeft int        `json:"recoveryCodesLeft"`
}

type totpSetup struct {
	URI    string `json:"uri"`
	Secret string `json:"secret"`
}

type recoveryCodes struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

// twoFactorOf is what me says of the User's 两步验证.
func (e *env) twoFactorOf(tok string) twoFactor {
	e.t.Helper()
	var got struct {
		TwoFactor twoFactor `json:"twoFactor"`
	}
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 {
		e.t.Fatalf("me: %d", c)
	}
	return got.TwoFactor
}

// A User turns 两步验证 on by adding the TOTP to an authenticator and
// typing one of its codes; only then is it on, and the 10 recovery codes
// are shown, that once.
func TestEnableTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)

	if got := e.twoFactorOf(tok); got.Enabled || got.RecoveryCodesLeft != 0 {
		t.Fatalf("before: %+v", got)
	}
	var first, setup totpSetup
	if c := e.call("POST", tok, "/v1/account/2fa/totp", nil, &first); c != 200 || len(first.Secret) != 32 {
		t.Fatalf("begin: %d %+v", c, first)
	}
	// Beginning again replaces the TOTP not yet confirmed.
	if c := e.call("POST", tok, "/v1/account/2fa/totp", nil, &setup); c != 200 || setup.Secret == first.Secret {
		t.Fatalf("begin again: %d %+v", c, setup)
	}
	host := strings.TrimPrefix(e.issuer, "http://")
	host = host[:strings.LastIndex(host, ":")]
	if want := "otpauth://totp/" + host + ":138%2A%2A%2A%2A8000?issuer=" + host + "&secret=" + setup.Secret; setup.URI != want {
		t.Errorf("uri %q, want %q", setup.URI, want)
	}
	if got := e.twoFactorOf(tok); got.Enabled {
		t.Fatalf("on before confirming: %+v", got)
	}

	now := time.Now()
	for _, wrong := range []string{totp(t, first.Secret, now), "12345"} {
		if c := e.call("POST", tok, "/v1/account/2fa/totp/confirm", map[string]string{"code": wrong}, nil); c != 422 {
			t.Errorf("confirm with %q: %d", wrong, c)
		}
	}
	var codes recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa/totp/confirm", map[string]string{"code": totp(t, setup.Secret, now)}, &codes); c != 200 {
		t.Fatalf("confirm: %d", c)
	}
	checkRecoveryCodes(t, codes.RecoveryCodes)
	if got := e.twoFactorOf(tok); !got.Enabled || got.EnabledAt == nil || got.RecoveryCodesLeft != 10 {
		t.Errorf("after: %+v", got)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/totp", nil, nil); c != 409 {
		t.Errorf("begin while on: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/totp/confirm", map[string]string{"code": totp(t, setup.Secret, now.Add(30*time.Second))}, nil); c != 409 {
		t.Errorf("confirm while on: %d", c)
	}
	e.audited(t, "mfa.enabled", 1)
}

// checkRecoveryCodes wants 10 distinct codes shaped xxxx-xxxx.
func checkRecoveryCodes(t *testing.T, codes []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range codes {
		if !regexp.MustCompile(`^[a-z2-7]{4}-[a-z2-7]{4}$`).MatchString(c) || seen[c] {
			t.Errorf("recovery code %q", c)
		}
		seen[c] = true
	}
	if len(codes) != 10 {
		t.Errorf("%d recovery codes", len(codes))
	}
}

// audited wants n events of a kind about ALICE, done by ALICE.
func (e *env) audited(t *testing.T, event string, n int) {
	t.Helper()
	var got int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_log WHERE sub = 'ALICE' AND event = $1 AND detail->>'by' = 'ALICE'", event).Scan(&got); err != nil || got != n {
		t.Errorf("%d %s events, want %d: %v", got, event, n, err)
	}
}

// enableTwoFactor turns 两步验证 on for the User tok is for.
func (e *env) enableTwoFactor(tok string) (secret string, codes []string) {
	e.t.Helper()
	var setup totpSetup
	var out recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa/totp", nil, &setup); c != 200 {
		e.t.Fatalf("begin: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/totp/confirm", map[string]string{"code": totp(e.t, setup.Secret, time.Now())}, &out); c != 200 {
		e.t.Fatalf("confirm: %d", c)
	}
	return setup.Secret, out.RecoveryCodes
}

// Turning 两步验证 on or off and regenerating the recovery codes need a
// recent authentication, and sign no other device out.
func TestManageTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "email:alice@example.com")
	tok := e.signIn("ALICE", 0)
	other := e.signIn("ALICE", time.Hour)

	for _, op := range [][2]string{{"POST", "/2fa/totp"}, {"POST", "/2fa/totp/confirm"}, {"DELETE", "/2fa"}, {"POST", "/2fa/recovery-codes"}} {
		if c := e.call(op[0], other, "/v1/account"+op[1], map[string]string{"code": "123456"}, nil); c != 403 {
			t.Errorf("%s %s without reauthentication: %d", op[0], op[1], c)
		}
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa", nil, nil); c != 422 {
		t.Errorf("turn off while off: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/recovery-codes", nil, nil); c != 422 {
		t.Errorf("regenerate while off: %d", c)
	}

	_, old := e.enableTwoFactor(tok)
	var codes recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa/recovery-codes", nil, &codes); c != 200 {
		t.Fatalf("regenerate: %d", c)
	}
	checkRecoveryCodes(t, codes.RecoveryCodes)
	for _, c := range codes.RecoveryCodes {
		if slices.Contains(old, c) {
			t.Errorf("old code %q again", c)
		}
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa", nil, nil); c != 204 {
		t.Fatalf("turn off: %d", c)
	}
	if got := e.twoFactorOf(other); got.Enabled || got.RecoveryCodesLeft != 0 {
		t.Errorf("after turning off, from the other Session: %+v", got)
	}
	e.audited(t, "mfa.enabled", 1)
	e.audited(t, "recovery_codes.regenerated", 1)
	e.audited(t, "mfa.disabled", 1)
}

// While 管理员必须启用两步验证 is on, a User holding a Management API Role
// can't turn 两步验证 off, though they can still regenerate recovery codes;
// other Users can.
func TestAdminsKeepTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "username:alice")
	e.user("BOB", "username:bob")
	if _, err := e.pool.Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO user_roles VALUES ('ALICE', '%s', 'readonly');
		UPDATE settings SET admins_need_two_factor = true`, identity.ManagementAPI)); err != nil {
		t.Fatal(err)
	}
	alice, bob := e.signIn("ALICE", 0), e.signIn("BOB", 0)
	e.enableTwoFactor(alice)
	e.enableTwoFactor(bob)

	if c := e.call("DELETE", alice, "/v1/account/2fa", nil, nil); c != 409 {
		t.Errorf("admin turns off: %d, want 409", c)
	}
	if got := e.twoFactorOf(alice); !got.Enabled {
		t.Errorf("admin's 两步验证 went off")
	}
	if c := e.call("POST", alice, "/v1/account/2fa/recovery-codes", nil, nil); c != 200 {
		t.Errorf("admin regenerates: %d", c)
	}
	if c := e.call("DELETE", bob, "/v1/account/2fa", nil, nil); c != 204 {
		t.Errorf("non-admin turns off: %d", c)
	}
}

// Deleting the account deletes the TOTP and recovery codes with it; the
// export says only whether 两步验证 is on, since when, and how many
// recovery codes are left.
func TestTwoFactorData(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	secret, codes := e.enableTwoFactor(tok)

	req, _ := http.NewRequest("GET", e.issuer+"/v1/account/export", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var got struct {
		Credentials struct {
			TwoFactor twoFactor `json:"twoFactor"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || !got.Credentials.TwoFactor.Enabled ||
		got.Credentials.TwoFactor.EnabledAt == nil || got.Credentials.TwoFactor.RecoveryCodesLeft != 10 {
		t.Errorf("export: %v %s", err, raw)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), codes[0]) {
		t.Errorf("export holds secrets: %s", raw)
	}

	if c := e.call("DELETE", tok, "/v1/account/me", nil, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT (SELECT count(*) FROM totp_credentials) + (SELECT count(*) FROM recovery_codes)").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows left: %v", n, err)
	}
}

// With 两步验证 on, only a TOTP code or a recovery code reauthenticates:
// a code to an Identifier or the password is refused. Each works once,
// and the Session's amr becomes otp + mfa.
func TestReauthenticationWithTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.password("ALICE", "password1")
	tok := e.signIn("ALICE", 0)
	secret, codes := e.enableTwoFactor(tok)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'on'; UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}

	if c := e.call("POST", tok, "/v1/account/reauth/code", map[string]string{"kind": "phone"}, nil); c != 422 {
		t.Errorf("send reauth code: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"password": "password1"}, nil); c != 422 {
		t.Errorf("reauth by password: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/recovery-codes", nil, nil); c != 403 {
		t.Fatalf("still not reauthenticated: %d", c)
	}

	// The code confirming 两步验证 was this step's; the next one is fresh.
	code := totp(t, secret, time.Now().Add(30*time.Second))
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"totp": "000000"}, nil); c != 422 {
		t.Errorf("wrong TOTP: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"totp": code}, nil); c != 204 {
		t.Fatalf("reauth by TOTP: %d", c)
	}
	var amr []string
	if err := e.pool.QueryRow(context.Background(), "SELECT amr FROM sessions").Scan(&amr); err != nil ||
		!slices.Equal(amr, []string{"otp", "mfa"}) {
		t.Errorf("amr %v: %v", amr, err)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"totp": code}, nil); c != 422 {
		t.Errorf("same TOTP again: %d", c)
	}

	upper := strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"recoveryCode": upper}, nil); c != 204 {
		t.Errorf("reauth by recovery code: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"recoveryCode": codes[0]}, nil); c != 422 {
		t.Errorf("same recovery code again: %d", c)
	}
	if got := e.twoFactorOf(tok); got.RecoveryCodesLeft != 9 {
		t.Errorf("after using one: %+v", got)
	}
	var used, failures int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_log WHERE sub = 'ALICE' AND event = 'recovery_code.used'").Scan(&used); err != nil || used != 1 {
		t.Errorf("%d recovery_code.used events: %v", used, err)
	}
	// Wrong TOTP and recovery codes count toward the IP lockout.
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM login_failures WHERE key LIKE 'ip:%'").Scan(&failures); err != nil || failures != 3 {
		t.Errorf("%d IP failures: %v", failures, err)
	}
}

func TestDeleteAccountRevokesApple(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	apple := appletest.Start(t)
	providers := provider.NewStore(e.pool, e.keyring)
	if err := providers.Create(ctx, "apple", "apple", "Apple", apple.Config()); err != nil {
		t.Fatal(err)
	}
	// Signed up with Apple, which is then disabled: deleting still revokes.
	to, err := providers.Begin(ctx, e.issuer, "apple", "authorization", "binder")
	if err != nil {
		t.Fatal(err)
	}
	form := apple.Approve(to)
	f, err := providers.Finish(ctx, e.issuer, "apple", form, "binder", "")
	if err != nil {
		t.Fatal(err)
	}
	sub := f.Sub
	if err := providers.SetEnabled(ctx, "apple", false); err != nil {
		t.Fatal(err)
	}

	if c := e.call("DELETE", e.signIn(sub, 0), "/v1/account/me", nil, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if len(apple.Revoked) != 1 || apple.Revoked[0].Get("token") != "rt-"+form.Get("code") {
		t.Errorf("revoked: %v", apple.Revoked)
	}
}

// 待激活的 User 拿不到令牌, 所以账号中心本来就进不去 (ADR 0016). 仍在这里
// 拦一道: "没有令牌"就是全部的保护, 万一有一张漏了出来, 它也不该打开账号
// 中心 —— 绑手机号、开两步验证都要求先激活。
func TestPendingUserCannotUseTheAccountCenter(t *testing.T) {
	e := start(t)
	e.user("ALICE", "email:alice@example.com")
	tok := e.signIn("ALICE", 0)
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET status = 'pending' WHERE id = 'ALICE'"); err != nil {
		t.Fatal(err)
	}

	for _, op := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/account/me", nil},
		{"PUT", "/v1/account/password", map[string]string{"password": "password1"}},
		{"POST", "/v1/account/2fa/totp", nil},
		{"PUT", "/v1/account/identifiers/phone", map[string]string{"value": "+8613800138000", "code": "123456"}},
	} {
		if c := e.call(op.method, tok, op.path, op.body, nil); c != 403 {
			t.Errorf("%s %s while 待激活: %d, want 403", op.method, op.path, c)
		}
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM passwords WHERE user_id = 'ALICE'").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d passwords, want 0: the account center wrote one", n)
	}
}
