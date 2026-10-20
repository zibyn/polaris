package account_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/passkey/passkeytest"
)

// enroll runs the adding flow for a: creation options, then the software
// authenticator's response. It returns the last status and the added
// Passkey's JSON.
func (e *env) enroll(tok string, a *passkeytest.Authenticator) (int, map[string]any) {
	e.t.Helper()
	var opts struct {
		Options json.RawMessage `json:"options"`
	}
	if code := e.call("POST", tok, "/v1/account/passkeys/options", nil, &opts); code != 200 {
		return code, nil
	}
	var added map[string]any
	return e.call("POST", tok, "/v1/account/passkeys", a.Enroll(opts.Options), &added), added
}

func (e *env) passkeys(tok string) (int, []map[string]any) {
	e.t.Helper()
	var got struct {
		Passkeys []map[string]any `json:"passkeys"`
	}
	code := e.call("GET", tok, "/v1/account/passkeys", nil, &got)
	return code, got.Passkeys
}

// passkey inserts a Passkey row for sub, as if added from the account center.
func (e *env) passkey(sub, name string) string {
	e.t.Helper()
	var id string
	err := e.pool.QueryRow(context.Background(), `
		INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, aaguid, backup_eligible, backup_state, name)
		VALUES ($1, decode(replace(gen_random_uuid()::text, '-', ''), 'hex'), '\x00'::bytea, 0, gen_random_uuid(), true, true, $2)
		RETURNING id`, sub, name).Scan(&id)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// A User adds Passkeys from the account center, names them, and deletes
// them; adding and deleting need a fresh authentication, renaming does not.
func TestPasskeys(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	a := passkeytest.New(t)
	a.Origin = e.issuer
	stale := e.signIn("ALICE", 20*time.Minute)
	tok := e.signIn("ALICE", 0)

	// Adding starts with reauthenticating.
	if code, _ := e.enroll(stale, a); code != 403 {
		t.Fatalf("add without reauthentication: %d", code)
	}
	var opts struct {
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				User      struct {
					ID string `json:"id"`
				} `json:"user"`
				RP struct {
					ID string `json:"id"`
				} `json:"rp"`
				AuthenticatorSelection struct {
					ResidentKey      string `json:"residentKey"`
					UserVerification string `json:"userVerification"`
				} `json:"authenticatorSelection"`
				Attestation        string `json:"attestation"`
				ExcludeCredentials []struct {
					ID string `json:"id"`
				} `json:"excludeCredentials"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if code := e.call("POST", tok, "/v1/account/passkeys/options", nil, &opts); code != 200 {
		t.Fatalf("options: %d", code)
	}
	pk := opts.Options.PublicKey
	rpID, _ := url.Parse(e.issuer)
	if pk.RP.ID != rpID.Hostname() || pk.Challenge == "" ||
		pk.AuthenticatorSelection.ResidentKey != "required" || pk.AuthenticatorSelection.UserVerification != "required" ||
		pk.Attestation != "none" || len(pk.ExcludeCredentials) != 0 {
		t.Fatalf("creation options: %+v", opts)
	}
	// The user handle is the User's sub.
	if handle, err := base64.RawURLEncoding.DecodeString(pk.User.ID); err != nil || string(handle) != "ALICE" {
		t.Fatalf("user handle: %q", pk.User.ID)
	}

	// An unknown authenticator's Passkey is just called Passkey.
	code, added := e.enroll(tok, a)
	if code != 200 || added["name"] != "Passkey" || added["lastUsedAt"] != nil {
		t.Fatalf("add: %d %+v", code, added)
	}
	id := added["id"].(string)
	if code, list := e.passkeys(tok); code != 200 || len(list) != 1 || list[0]["id"] != id ||
		list[0]["createdAt"] == nil {
		t.Fatalf("list: %d %+v", code, list)
	}

	// The next options exclude the credential just added; submitting the
	// same credential again is refused anyway.
	if code := e.call("POST", tok, "/v1/account/passkeys/options", nil, &opts); code != 200 ||
		len(opts.Options.PublicKey.ExcludeCredentials) != 1 {
		t.Fatalf("excludeCredentials: %d %+v", code, opts)
	}
	a.CredentialID = mustDecodeB64(t, opts.Options.PublicKey.ExcludeCredentials[0].ID)
	if code, _ := e.enroll(tok, a); code != 409 {
		t.Fatalf("the same credential again: %d", code)
	}

	// A Passkey's name is its owner's business; no reauthentication.
	if code := e.call("PATCH", stale, "/v1/account/passkeys/"+id, map[string]string{"name": "工作电脑"}, nil); code != 204 {
		t.Fatalf("rename: %d", code)
	}
	if code, list := e.passkeys(tok); code != 200 || len(list) != 1 || list[0]["name"] != "工作电脑" {
		t.Fatalf("list after rename: %d %+v", code, list)
	}
	if code := e.call("PATCH", tok, "/v1/account/passkeys/nope", map[string]string{"name": "x"}, nil); code != 404 {
		t.Errorf("rename a Passkey that is not theirs: %d", code)
	}
	if code := e.call("PATCH", tok, "/v1/account/passkeys/"+id, map[string]string{"name": " "}, nil); code != 422 {
		t.Errorf("rename to nothing: %d", code)
	}

	// Deleting needs reauthentication again.
	if code := e.call("DELETE", stale, "/v1/account/passkeys/"+id, nil, nil); code != 403 {
		t.Fatalf("delete without reauthentication: %d", code)
	}
	if code := e.call("DELETE", tok, "/v1/account/passkeys/"+id, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, list := e.passkeys(tok); code != 200 || len(list) != 0 {
		t.Fatalf("list after delete: %d %+v", code, list)
	}
	if code := e.call("DELETE", tok, "/v1/account/passkeys/"+id, nil, nil); code != 404 {
		t.Errorf("delete again: %d", code)
	}

	// Every change of the list is audited.
	rows, err := e.pool.Query(context.Background(), "SELECT event, detail->>'by', detail->>'name' FROM audit_log WHERE sub = 'ALICE' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events [][3]string
	for rows.Next() {
		var ev [3]string
		if err := rows.Scan(&ev[0], &ev[1], &ev[2]); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	want := [][3]string{
		{"passkey.added", "ALICE", "Passkey"}, {"passkey.renamed", "ALICE", "工作电脑"},
		{"passkey.removed", "ALICE", "工作电脑"},
	}
	if len(events) != len(want) {
		t.Fatalf("audit: %+v", events)
	}
	for i, ev := range events {
		if ev != want[i] {
			t.Errorf("audit %d: %v, want %v", i, ev, want[i])
		}
	}
}

// A Passkey without the User Verification flag is refused: a Passkey is
// one because it verifies the User every time.
func TestPasskeyNeedsUserVerification(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin, a.UV = e.issuer, false

	if code, _ := e.enroll(tok, a); code != 422 {
		t.Fatalf("add without UV: %d", code)
	}
	if code, list := e.passkeys(tok); code != 200 || len(list) != 0 {
		t.Fatalf("list: %d %+v", code, list)
	}
}

// While 管理员必须启用两步验证或 Passkey is on, a User holding a Management
// API Role may turn 两步验证 off once a Passkey is left, but may not delete
// their last Passkey while nothing else satisfies the switch.
func TestAdminKeepsPasskeyOrTwoFactor(t *testing.T) {
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
	second := e.passkey("ALICE", "手机")
	last := e.passkey("ALICE", "工作电脑")

	// A Passkey left satisfies the switch, so 两步验证 may go off.
	if c := e.call("DELETE", alice, "/v1/account/2fa", nil, nil); c != 204 {
		t.Fatalf("turn off with a Passkey: %d", c)
	}
	// One of two Passkeys goes; the last one stays.
	if c := e.call("DELETE", alice, "/v1/account/passkeys/"+second, nil, nil); c != 204 {
		t.Fatalf("delete one of two: %d", c)
	}
	if c := e.call("DELETE", alice, "/v1/account/passkeys/"+last, nil, nil); c != 409 {
		t.Fatalf("delete the last: %d, want 409", c)
	}
	if code, list := e.passkeys(alice); code != 200 || len(list) != 1 {
		t.Fatalf("the last Passkey kept: %d %+v", code, list)
	}
	// Turning 两步验证 back on takes the guard off.
	e.enableTwoFactor(alice)
	if c := e.call("DELETE", alice, "/v1/account/passkeys/"+last, nil, nil); c != 204 {
		t.Fatalf("delete the last with 两步验证 on: %d", c)
	}

	// Without a Role, the last Passkey goes like any other.
	lastBob := e.passkey("BOB", "工作电脑")
	if c := e.call("DELETE", bob, "/v1/account/passkeys/"+lastBob, nil, nil); c != 204 {
		t.Errorf("no Role, delete the last: %d", c)
	}
}

// A Passkey's default name is its authenticator's, from the AAGUID.
func TestPasskeyName(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin = e.issuer
	// 1Password's AAGUID.
	u, err := uuid.Parse("bada5566-a7aa-401f-bd96-45619a55120d")
	if err != nil {
		t.Fatal(err)
	}
	a.AAGUID = u
	if code, added := e.enroll(tok, a); code != 200 || added["name"] != "1Password" {
		t.Fatalf("add: %d %+v", code, added)
	}
}

// The challenge is one attempt: a replayed or stale response gets nothing.
func TestPasskeyChallengeIsOneAttempt(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin = e.issuer

	var opts struct {
		Options json.RawMessage `json:"options"`
	}
	if code := e.call("POST", tok, "/v1/account/passkeys/options", nil, &opts); code != 200 {
		t.Fatalf("options: %d", code)
	}
	response := a.Enroll(opts.Options)
	if code := e.call("POST", tok, "/v1/account/passkeys", response, nil); code != 200 {
		t.Fatalf("add: %d", code)
	}
	if code := e.call("POST", tok, "/v1/account/passkeys", response, nil); code != 422 {
		t.Fatalf("replay: %d", code)
	}
	if code := e.call("POST", tok, "/v1/account/passkeys", a.Enroll(opts.Options), nil); code != 422 {
		t.Fatalf("challenge reused: %d", code)
	}
}

// Native Apps use the same endpoints with their own bearer token, from a
// Session of their own.
func TestPasskeysFromAnAppSession(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	if _, err := e.pool.Exec(context.Background(), "UPDATE sessions SET client_id = 'com.example.app'"); err != nil {
		t.Fatal(err)
	}
	a := passkeytest.New(t)
	a.Origin = e.issuer
	if code, added := e.enroll(tok, a); code != 200 || added["name"] != "Passkey" {
		t.Fatalf("add from an App Session: %d %+v", code, added)
	}
}

// /.well-known/passkey-endpoints tells password managers where adding and
// managing Passkeys happens.
func TestPasskeyEndpointsWellKnown(t *testing.T) {
	e := start(t)
	resp, err := http.Get(e.issuer + "/.well-known/passkey-endpoints")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	if resp.StatusCode != 200 || json.Unmarshal(body, &got) != nil ||
		got["enroll"] != e.issuer+"/account#passkeys" || got["manage"] != e.issuer+"/account#passkeys" {
		t.Fatalf("passkey-endpoints: %d %s", resp.StatusCode, body)
	}
}

// setPasskeyLogin turns the instance's Passkey switch on or off.
func (e *env) setPasskeyLogin(on bool) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET passkey_login = $1", on); err != nil {
		e.t.Fatal(err)
	}
}

// With Passkey login off the account center offers no way to add or
// reauthenticate with a Passkey, and /.well-known/passkey-endpoints is gone;
// the Passkeys already added are kept and work once it is back on
// (docs/spec/consoles.md#设置).
func TestPasskeyLoginOff(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	if code, _ := e.enroll(tok, a); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	e.setPasskeyLogin(false)

	// /me tells the account center to hide the Passkey section and its
	// reauthentication way.
	var me struct {
		PasskeyLogin bool `json:"passkeyLogin"`
	}
	if code := e.call("GET", tok, "/v1/account/me", nil, &me); code != 200 || me.PasskeyLogin {
		t.Fatalf("me while off: %d %+v", code, me)
	}
	// Adding one is refused, and so is starting the reauthentication ceremony.
	if code, _ := e.enroll(tok, a); code != 422 {
		t.Fatalf("add while off: %d, want 422", code)
	}
	if code := e.call("POST", tok, "/v1/account/reauth/passkey", nil, nil); code != 422 {
		t.Fatalf("begin passkey reauth while off: %d, want 422", code)
	}
	// The discovery file is gone.
	resp, err := http.Get(e.issuer + "/.well-known/passkey-endpoints")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("passkey-endpoints while off: %d, want 404", resp.StatusCode)
	}

	// The Passkey added before is kept: it still lists.
	if code, list := e.passkeys(tok); code != 200 || len(list) != 1 {
		t.Fatalf("the Passkey kept: %d %+v", code, list)
	}

	// Back on, the Passkey works again.
	e.setPasskeyLogin(true)
	if options := e.passkeyReauthOptions(tok, 200); options == nil {
		t.Fatal("no reauthentication options once Passkey login is back on")
	}
}

// mustDecodeB64 decodes a base64url credential ID from options.
func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// passkeyReauthOptions begins a Passkey reauthentication and returns the
// assertion options, failing the test unless the status is want.
func (e *env) passkeyReauthOptions(tok string, want int) json.RawMessage {
	e.t.Helper()
	var out struct {
		Options json.RawMessage `json:"options"`
	}
	if code := e.call("POST", tok, "/v1/account/reauth/passkey", nil, &out); code != want {
		e.t.Fatalf("passkey reauth options: %d, want %d", code, want)
	}
	return out.Options
}

// reauthPasskey submits an assertion to reauthenticate and returns the status.
func (e *env) reauthPasskey(tok string, assertion json.RawMessage) int {
	e.t.Helper()
	return e.call("POST", tok, "/v1/account/reauth", map[string]string{"passkey": string(assertion)}, nil)
}

// A User with a Passkey reauthenticates with it before a sensitive action:
// the options name only their own Passkeys, and the Session's amr and
// auth_time come out as after a Passkey sign-in.
func TestPasskeyReauthentication(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	if code, added := e.enroll(tok, a); code != 200 {
		t.Fatalf("enroll: %d %+v", code, added)
	}
	// The Session's authentication ages; a sensitive action is refused.
	if _, err := e.pool.Exec(context.Background(), "UPDATE sessions SET auth_time = now() - interval '20 minutes'"); err != nil {
		t.Fatal(err)
	}
	if code := e.call("GET", tok, "/v1/account/export", nil, nil); code != 403 {
		t.Fatalf("export before reauthentication: %d", code)
	}

	options := e.passkeyReauthOptions(tok, 200)
	var pk struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &pk); err != nil {
		t.Fatalf("options: %v: %s", err, options)
	}
	if pk.PublicKey.Challenge == "" || pk.PublicKey.UserVerification != "required" || len(pk.PublicKey.AllowCredentials) != 1 {
		t.Fatalf("assertion options: %s", options)
	}

	// Without User Verification the assertion is refused, as at login.
	a.UV = false
	if code := e.reauthPasskey(tok, a.Assert(options)); code != 422 {
		t.Fatalf("reauth without UV: %d", code)
	}
	a.UV = true

	// The refused assertion spent the challenge; a fresh ceremony passes.
	options = e.passkeyReauthOptions(tok, 200)
	a.SignCount = 1
	if code := e.reauthPasskey(tok, a.Assert(options)); code != 204 {
		t.Fatalf("reauth: %d", code)
	}
	var amr []string
	var authTime time.Time
	if err := e.pool.QueryRow(context.Background(), "SELECT amr, auth_time FROM sessions").Scan(&amr, &authTime); err != nil ||
		!slices.Equal(amr, []string{"hwk", "mfa"}) || time.Since(authTime) > time.Minute {
		t.Fatalf("after reauth: amr %v, auth_time %v: %v", amr, authTime, err)
	}
	if code := e.call("GET", tok, "/v1/account/export", nil, nil); code != 200 {
		t.Fatalf("export after reauthentication: %d", code)
	}
}

// With 两步验证 on, a Passkey also reauthenticates, as it signs the User in
// past the TOTP.
func TestPasskeyReauthPastTOTP(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	if code, _ := e.enroll(tok, a); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	e.enableTwoFactor(tok)
	if _, err := e.pool.Exec(context.Background(), "UPDATE sessions SET auth_time = now() - interval '20 minutes'"); err != nil {
		t.Fatal(err)
	}
	options := e.passkeyReauthOptions(tok, 200)
	a.SignCount = 1
	if code := e.reauthPasskey(tok, a.Assert(options)); code != 204 {
		t.Fatalf("reauth with 两步验证 on: %d", code)
	}
}

// A User's own Passkey passes; another User's does not, and a counter that
// went backwards is refused and audited like at login.
func TestPasskeyReauthRefused(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "username:bob")
	alice, bob := e.signIn("ALICE", 0), e.signIn("BOB", 0)
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	if code, _ := e.enroll(alice, a); code != 200 {
		t.Fatalf("enroll ALICE: %d", code)
	}
	b := passkeytest.New(t)
	b.Origin, b.UserHandle = e.issuer, []byte("BOB")
	if code, _ := e.enroll(bob, b); code != 200 {
		t.Fatalf("enroll BOB: %d", code)
	}

	// BOB's Passkey on ALICE's ceremony reauthenticates nobody.
	b.SignCount = 1
	if code := e.reauthPasskey(alice, b.Assert(e.passkeyReauthOptions(alice, 200))); code != 422 {
		t.Fatalf("another User's Passkey: %d", code)
	}

	a.SignCount = 1
	if code := e.reauthPasskey(alice, a.Assert(e.passkeyReauthOptions(alice, 200))); code != 204 {
		t.Fatalf("the User's own Passkey: %d", code)
	}

	// The counter goes backwards: refused, and audited.
	a.SignCount = 0
	if code := e.reauthPasskey(alice, a.Assert(e.passkeyReauthOptions(alice, 200))); code != 422 {
		t.Fatalf("a counter that went backwards: %d", code)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_log WHERE event = 'passkey.counter_regressed' AND sub = 'ALICE'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("counter audit: %d: %v", n, err)
	}
}

// A User without a Passkey has nothing to reauthenticate with.
func TestPasskeyReauthWithoutAPasskey(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	e.passkeyReauthOptions(tok, 422)
}
