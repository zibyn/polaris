package oidcstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// KeyRetention is how long an old key stays published after the next one
// arrives: the longest token lifetime (10 min) plus room for RP JWKS caches.
const KeyRetention = time.Hour

// KeyLifetime is how long the newest key signs before RotateDue replaces it.
const KeyLifetime = 90 * 24 * time.Hour

var keyRetention = pgtype.Interval{Microseconds: KeyRetention.Microseconds(), Valid: true}

// Keys holds the RS256 signing keys, sealed with the master key. The newest
// key signs; older ones stay published for KeyRetention after their successor
// arrives so tokens they signed verify until they expire.
type Keys struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	keyring *crypt.Keyring
}

func NewKeys(pool *pgxpool.Pool, keyring *crypt.Keyring) *Keys {
	return &Keys{pool: pool, q: sqlc.New(pool), keyring: keyring}
}

// Ensure creates the first signing key if there is none. Replicas starting
// together may all try; the first key's generation lets one in.
func (k *Keys) Ensure(ctx context.Context) error {
	return db.Retry(ctx, k.pool, func(tx pgx.Tx) error {
		q := k.q.WithTx(tx)
		keys, err := q.SigningKeys(ctx, keyRetention)
		if err != nil || len(keys) > 0 {
			return err
		}
		return add(ctx, q, k.keyring, 1)
	})
}

// Rotate makes a new key current and audits it as done by by. The old ones
// retire by age (see KeyRetention); the hourly cleanup deletes them.
func (k *Keys) Rotate(ctx context.Context, by audit.Actor) error {
	return db.Retry(ctx, k.pool, func(tx pgx.Tx) error {
		q := k.q.WithTx(tx)
		keys, err := q.SigningKeys(ctx, keyRetention)
		if err != nil {
			return err
		}
		return k.rotate(ctx, q, keys, by)
	})
}

// RotateDue makes a new key current once the newest is KeyLifetime old, and
// audits it. Every replica runs it hourly; the generation keeps it to one,
// and the others find a fresh key when they try again.
func (k *Keys) RotateDue(ctx context.Context) error {
	return db.Retry(ctx, k.pool, func(tx pgx.Tx) error {
		q := k.q.WithTx(tx)
		keys, err := q.SigningKeys(ctx, keyRetention)
		if err != nil || len(keys) == 0 || time.Since(keys[0].CreatedAt.Time) < KeyLifetime {
			return err
		}
		return k.rotate(ctx, q, keys, audit.System)
	})
}

// rotate adds the successor of keys[0], the newest of the published keys.
func (k *Keys) rotate(ctx context.Context, q *sqlc.Queries, keys []sqlc.SigningKey, by audit.Actor) error {
	next := int64(1)
	if len(keys) > 0 {
		next = keys[0].Generation + 1
	}
	if err := add(ctx, q, k.keyring, next); err != nil {
		return err
	}
	detail := by.Detail(nil)
	return q.Audit(ctx, sqlc.AuditParams{Event: "keys.rotated", Detail: detail})
}

// Published lists the keys in the JWKS, newest (current) first.
func (k *Keys) Published(ctx context.Context) ([]sqlc.SigningKey, error) {
	return k.q.SigningKeys(ctx, keyRetention)
}

// JWKS returns the published keys with their private halves, newest first:
// go-oidc signs with the first RS256 key and strips private parts when serving.
// ponytail: reads PG on every call; cache for a few seconds if it shows up in profiles.
func (k *Keys) JWKS(ctx context.Context) (goidc.JSONWebKeySet, error) {
	rows, err := k.Published(ctx)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}
	var jwks goidc.JSONWebKeySet
	for _, row := range rows {
		der, err := k.keyring.Open(row.Sealed, keyAAD(row.Kid))
		if err != nil {
			return goidc.JSONWebKeySet{}, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return goidc.JSONWebKeySet{}, err
		}
		jwks.Keys = append(jwks.Keys, goidc.JSONWebKey{
			Key:       key,
			KeyID:     row.Kid,
			Algorithm: string(goidc.SigAlgRS256),
			Use:       string(goidc.KeyUsageSignature),
		})
	}
	return jwks, nil
}

// add inserts a new key as generation; db.ErrConflict when another replica
// took that generation first.
func add(ctx context.Context, q *sqlc.Queries, keyring *crypt.Keyring, generation int64) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	kid := rand.Text()
	sealed, err := keyring.Seal(der, keyAAD(kid))
	if err != nil {
		return err
	}
	err = q.InsertSigningKey(ctx, sqlc.InsertSigningKeyParams{Kid: kid, Sealed: sealed, Generation: generation})
	if pg := (*pgconn.PgError)(nil); errors.As(err, &pg) && pg.ConstraintName == "signing_keys_generation_key" {
		return db.ErrConflict
	}
	return err
}

func keyAAD(kid string) []byte { return []byte("signing_key:" + kid) }

// LogoutToken signs an OIDC Back-Channel Logout 1.0 logout token (section 2.4)
// telling Application aud that the Session sid of User sub has ended.
func (k *Keys) LogoutToken(ctx context.Context, issuer, aud, sub, sid string) (string, error) {
	jwks, err := k.JWKS(ctx)
	if err != nil {
		return "", err
	}
	if len(jwks.Keys) == 0 {
		return "", errors.New("no signing key")
	}
	key := jwks.Keys[0]
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key.Key, KeyID: key.KeyID}},
		(&jose.SignerOptions{}).WithType("logout+jwt"))
	if err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Signed(signer).Claims(map[string]any{
		"iss": issuer, "aud": aud, "sub": sub, "sid": sid,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": rand.Text(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}).Serialize()
}
