package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/passkey/passkeytest"
)

// start gives the module an empty database, one User, and a software
// authenticator whose assertions that User's Passkeys sign. It returns the
// User's sub.
func start(t *testing.T) (*passkey.Store, *passkeytest.Authenticator, *pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := identity.New(pool, keyring).SignIn(ctx, "phone", "+8613800138000")
	if err != nil {
		t.Fatal(err)
	}
	// The account center's registration challenge hangs off a Session.
	if _, err := pool.Exec(ctx,
		"INSERT INTO sessions (id, id_hash, user_id, auth_time, amr) VALUES ('enroll-session', '\x01', $1, now(), '{}')", sub); err != nil {
		t.Fatal(err)
	}
	store, err := passkey.New(pool, "https://rp.example")
	if err != nil {
		t.Fatal(err)
	}
	a := passkeytest.New(t)
	a.Origin = "https://rp.example"
	a.UserHandle = []byte(sub)
	return store, a, pool, sub
}

// enroll adds one of a's Passkeys to sub's account, as the account center
// API does.
func enroll(t *testing.T, store *passkey.Store, a *passkeytest.Authenticator, sub string) {
	t.Helper()
	ctx := context.Background()
	options, err := store.Begin(ctx, sub, sub, "enroll-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finish(ctx, sub, "enroll-session", a.Enroll(options)); err != nil {
		t.Fatal(err)
	}
}

// assertionOptions holds what a login's options JSON must say.
type assertionOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []any  `json:"allowCredentials"`
		Timeout          int    `json:"timeout"`
	} `json:"publicKey"`
}

// A Passkey signs its User in: the options are a discoverable ceremony, the
// assertion passes, and the sign-in marks the Passkey used.
func TestPasskeySignIn(t *testing.T) {
	store, a, pool, sub := start(t)
	enroll(t, store, a, sub)

	raw, challenge, err := store.LoginOptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var opts assertionOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatal(err)
	}
	if host, _ := url.Parse("https://rp.example"); opts.PublicKey.RPID != host.Hostname() ||
		opts.PublicKey.Challenge == "" || opts.PublicKey.UserVerification != "required" ||
		len(opts.PublicKey.AllowCredentials) != 0 || opts.PublicKey.Timeout == 0 {
		t.Fatalf("assertion options: %s", raw)
	}

	a.SignCount = 3
	in, err := store.SignIn(context.Background(), challenge, a.Assert(raw))
	if err != nil {
		t.Fatal(err)
	}
	if in.Sub != sub || in.BackupEligible {
		t.Fatalf("signed in as %+v", in)
	}
	var signCount int64
	var lastUsed *bool
	if err := pool.QueryRow(context.Background(),
		"SELECT sign_count, last_used_at IS NOT NULL FROM passkeys").Scan(&signCount, &lastUsed); err != nil {
		t.Fatal(err)
	}
	if signCount != 3 || !*lastUsed {
		t.Fatalf("sign_count %d, last_used_at set %v", signCount, *lastUsed)
	}
}

// What a sign-in refuses: a credential nobody added, a wrong signature, a
// missing User Verification, an assertion signed for another challenge, and
// one for a challenge nobody issued.
func TestPasskeySignInRefused(t *testing.T) {
	store, a, pool, sub := start(t)
	enroll(t, store, a, sub)
	ctx := context.Background()
	raw, challenge, _ := store.LoginOptions(context.Background())

	unknown := passkeytest.New(t)
	unknown.Origin, unknown.UserHandle = a.Origin, a.UserHandle
	if other, _, err := store.LoginOptions(context.Background()); err != nil {
		t.Fatal(err)
	} else if _, err := store.SignIn(ctx, challenge, unknown.Assert(other)); !errors.Is(err, passkey.ErrNoPasskey) {
		t.Fatalf("an unknown credential: %v", err)
	}

	a.SignCount = 5
	signed := a.Assert(raw)
	var tampered map[string]any
	if err := json.Unmarshal(signed, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["response"].(map[string]any)["signature"] = "c2ln"
	if wrong, err := json.Marshal(tampered); err != nil {
		t.Fatal(err)
	} else if _, err := store.SignIn(ctx, challenge, wrong); !errors.Is(err, passkey.ErrLoginFail) {
		t.Fatalf("a wrong signature: %v", err)
	}

	// An enrolled authenticator that skips verifying the User at sign-in.
	noUV := passkeytest.New(t)
	noUV.Origin, noUV.UserHandle = a.Origin, a.UserHandle
	enroll(t, store, noUV, sub)
	noUV.UV = false
	if _, err := store.SignIn(ctx, challenge, noUV.Assert(raw)); !errors.Is(err, passkey.ErrLoginFail) {
		t.Fatalf("no User Verification: %v", err)
	}

	// A fresh challenge for the same page: the old assertion no longer fits.
	if _, other, err := store.LoginOptions(context.Background()); err != nil {
		t.Fatal(err)
	} else if _, err := store.SignIn(ctx, other, a.Assert(raw)); !errors.Is(err, passkey.ErrLoginFail) {
		t.Fatalf("another challenge's assertion: %v", err)
	}
	if _, err := store.SignIn(ctx, "a-challenge-nobody-issued", a.Assert(raw)); !errors.Is(err, passkey.ErrLoginFail) {
		t.Fatalf("a challenge nobody issued: %v", err)
	}

	// Nothing above signed anyone in.
	var events int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_log WHERE event != 'passkey.added'").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("audit events for refused sign-ins: %d", events)
	}
}

// A counter that went backwards is refused and audited.
func TestPasskeyCounterRegression(t *testing.T) {
	store, a, pool, sub := start(t)
	enroll(t, store, a, sub)
	ctx := context.Background()
	raw, challenge, _ := store.LoginOptions(context.Background())

	a.SignCount = 5
	if _, err := store.SignIn(ctx, challenge, a.Assert(raw)); err != nil {
		t.Fatal(err)
	}
	raw, challenge, _ = store.LoginOptions(context.Background())
	a.SignCount = 4
	if _, err := store.SignIn(ctx, challenge, a.Assert(raw)); !errors.Is(err, passkey.ErrCloned) {
		t.Fatalf("counter regressed: %v", err)
	}
	var name string
	var count int64
	if err := pool.QueryRow(ctx,
		"SELECT detail->>'name', (detail->>'count')::bigint FROM audit_log WHERE event = 'passkey.counter_regressed'").
		Scan(&name, &count); err != nil {
		t.Fatalf("no audit for the regression: %v", err)
	}
	if name != "Passkey" || count != 4 {
		t.Fatalf("audit: %q %d", name, count)
	}
}

// A synced Passkey (backup eligible) says so, for the amr that says swk.
func TestPasskeySignInSynced(t *testing.T) {
	store, a, _, sub := start(t)
	a.BE, a.BS = true, true
	enroll(t, store, a, sub)

	raw, challenge, _ := store.LoginOptions(context.Background())
	a.SignCount = 1
	in, err := store.SignIn(context.Background(), challenge, a.Assert(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !in.BackupEligible {
		t.Fatal("a synced Passkey should be backup eligible")
	}
}
