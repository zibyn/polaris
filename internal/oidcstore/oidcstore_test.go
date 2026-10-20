package oidcstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

func setup(t *testing.T) (*pgxpool.Pool, *crypt.Keyring) {
	t.Helper()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return pool, keyring
}

func sign(t *testing.T, key goidc.JSONWebKey) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{Subject: "u"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// verify checks tok against the public half of jwks, as a relying party would.
func verify(t *testing.T, jwks goidc.JSONWebKeySet, tok string) error {
	t.Helper()
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return err
	}
	key, err := jwks.Public().Key(parsed.Headers[0].KeyID)
	if err != nil {
		return err
	}
	return parsed.Claims(key, &jwt.Claims{})
}

func TestSigningKeySurvivesRestart(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()

	if err := NewKeys(pool, keyring).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := NewKeys(pool, keyring).JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A restart is a new Keys on the same database.
	restarted := NewKeys(pool, keyring)
	if err := restarted.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := restarted.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Keys) != 1 || second.Keys[0].KeyID != first.Keys[0].KeyID {
		t.Fatalf("keys after restart = %v, want just %s", second.Keys, first.Keys[0].KeyID)
	}
	if k := second.Keys[0]; k.Algorithm != "RS256" || k.Use != "sig" || k.IsPublic() {
		t.Fatalf("key = alg %s use %s public %v, want a private RS256 sig key", k.Algorithm, k.Use, k.IsPublic())
	}
}

func TestSigningKeyIsSealed(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	if err := NewKeys(pool, keyring).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	other, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeys(pool, other).JWKS(ctx); err == nil {
		t.Fatal("JWKS opened the signing key with the wrong master key")
	}
}

func TestRotationKeepsPreviousKey(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	keys := NewKeys(pool, keyring)
	if err := keys.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := keys.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldToken := sign(t, before.Keys[0])

	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := keys.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Keys) != 2 || after.Keys[1].KeyID != before.Keys[0].KeyID {
		t.Fatalf("after rotation = %v, want [new, %s]", after.Keys, before.Keys[0].KeyID)
	}
	if err := verify(t, after, oldToken); err != nil {
		t.Fatalf("token signed before rotation no longer verifies: %v", err)
	}
	if err := verify(t, after, sign(t, after.Keys[0])); err != nil {
		t.Fatalf("token signed with the new key does not verify: %v", err)
	}

	// The next rotation retires the original key.
	if err := keys.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	last, err := keys.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Keys) != 2 || last.Keys[1].KeyID != after.Keys[0].KeyID {
		t.Fatalf("after second rotation = %v, want [newest, %s]", last.Keys, after.Keys[0].KeyID)
	}
	if err := verify(t, last, oldToken); err == nil {
		t.Fatal("token from a retired key still verifies")
	}
}

func TestGrant(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)

	g := &goidc.Grant{
		ID:                "grant",
		Subject:           "user",
		ClientID:          "client",
		AuthCode:          "the-auth-code",
		AuthCodeExpiresAt: int(time.Now().Add(time.Minute).Unix()),
		RefreshToken:      "the-refresh-token",
		Store:             map[string]any{"claim": "value", "auth_time": 1791302791, "nested": map[string]any{"n": 2}, "ratio": 0.5},
	}
	if err := s.SaveGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	for name, load := range map[string]func() (*goidc.Grant, error){
		"by id":            func() (*goidc.Grant, error) { return s.Grant(ctx, "grant") },
		"by auth code":     func() (*goidc.Grant, error) { return s.GrantByAuthCode(ctx, "the-auth-code") },
		"by refresh token": func() (*goidc.Grant, error) { return s.GrantByRefreshToken(ctx, "the-refresh-token") },
	} {
		got, err := load()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.ID != g.ID || got.AuthCode != g.AuthCode || got.RefreshToken != g.RefreshToken || got.Store["claim"] != "value" {
			t.Fatalf("%s: got %+v", name, got)
		}
		// Integers must stay integers: claims such as auth_time are re-signed
		// from the store, and a float would be serialised as 1.791302791e+09.
		if got.Store["auth_time"] != int64(1791302791) || got.Store["nested"].(map[string]any)["n"] != int64(2) || got.Store["ratio"] != 0.5 {
			t.Fatalf("%s: store numbers = %#v", name, got.Store)
		}
	}

	// Rotating the refresh token moves the lookup to the new one.
	g.RefreshToken = "rotated"
	if err := s.SaveGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantByRefreshToken(ctx, "the-refresh-token"); !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("old refresh token: err = %v, want ErrNotFound", err)
	}
	if _, err := s.GrantByRefreshToken(ctx, "rotated"); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT sealed FROM oidc_grants`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("the-auth-code")) || bytes.Contains(raw, []byte("rotated")) {
		t.Fatal("grant secrets stored in the clear")
	}

	if _, err := s.Grant(ctx, "missing"); !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("missing grant: err = %v, want ErrNotFound", err)
	}
}

func TestGrantExpiry(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)
	s.GrantTTL = -time.Second // anything without a longer-lived secret is already gone

	if err := s.SaveGrant(ctx, &goidc.Grant{ID: "short"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Grant(ctx, "short"); !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("expired grant: err = %v, want ErrNotFound", err)
	}
	refresh := &goidc.Grant{ID: "refresh", RefreshToken: "rt", RefreshTokenExpiresAt: int(time.Now().Add(time.Hour).Unix())}
	if err := s.SaveGrant(ctx, refresh); err != nil {
		t.Fatal(err)
	}
	forever := &goidc.Grant{ID: "forever", RefreshToken: "rt2"}
	if err := s.SaveGrant(ctx, forever); err != nil {
		t.Fatal(err)
	}

	if err := DeleteExpired(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var ids []string
	rows, err := pool.Query(ctx, `SELECT id FROM oidc_grants ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] != "forever" || ids[1] != "refresh" {
		t.Fatalf("grants after cleanup = %v, want [forever refresh]", ids)
	}
}

func TestSessions(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)
	later := int(time.Now().Add(time.Minute).Unix())
	earlier := int(time.Now().Add(-time.Minute).Unix())

	if err := s.SaveSession(ctx, &goidc.AuthnSession{ID: "as", ExpiresAt: later, Store: map[string]any{"k": "v", "auth_time": later}}); err != nil {
		t.Fatal(err)
	}
	as, err := s.Session(ctx, "as")
	if err != nil || as.Store["k"] != "v" || as.Store["auth_time"] != int64(later) {
		t.Fatalf("authn session = %+v, %v", as, err)
	}
	if err := s.SaveLogoutSession(ctx, &goidc.LogoutSession{ID: "ls", ExpiresAt: later, ClientID: "c"}); err != nil {
		t.Fatal(err)
	}
	ls, err := s.LogoutSession(ctx, "ls")
	if err != nil || ls.ClientID != "c" {
		t.Fatalf("logout session = %+v, %v", ls, err)
	}

	if err := s.SaveSession(ctx, &goidc.AuthnSession{ID: "old", ExpiresAt: earlier}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "old"); !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("expired session: err = %v, want ErrNotFound", err)
	}
	if err := DeleteExpired(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oidc_authn_sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("authn sessions after cleanup = %d, want 1", n)
	}
}

func TestClient(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)
	s.Scopes = "openid profile"

	console, err := s.Client(ctx, "polaris-console")
	if err != nil {
		t.Fatal(err)
	}
	if !console.IsPublic() || console.Secret != "" {
		t.Fatalf("built-in console = %+v, want a public client", console)
	}

	if err := CreateApplication(ctx, pool, Application{
		ClientID:               "backend",
		Name:                   "Backend",
		Secret:                 "s3cret",
		RedirectURIs:           []string{"https://app.example.com/cb"},
		PostLogoutRedirectURIs: []string{"https://app.example.com/bye"},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Client(ctx, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if c.IsPublic() || c.TokenAuthnMethod != goidc.AuthnMethodSecretBasic ||
		c.RedirectURIs[0] != "https://app.example.com/cb" || c.PostLogoutRedirectURIs[0] != "https://app.example.com/bye" ||
		c.ScopeIDs != "openid profile" {
		t.Fatalf("confidential client = %+v", c)
	}
	if err := VerifyClientSecret(ctx, c.Secret, "s3cret"); err != nil {
		t.Fatalf("right secret rejected: %v", err)
	}
	if err := VerifyClientSecret(ctx, c.Secret, "wrong"); err == nil {
		t.Fatal("wrong secret accepted")
	}

	if _, err := s.Client(ctx, "missing"); !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("missing client: err = %v, want ErrNotFound", err)
	}
}

func TestReplicasStartingTogetherCreateOneKey(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	var g errgroup.Group
	for range 4 {
		g.Go(func() error { return NewKeys(pool, keyring).Ensure(ctx) })
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("signing keys = %d, want 1", n)
	}
}
