package oidcstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// KeyRetention is how long an old key stays published after the next one
// arrives: the longest token lifetime (10 min) plus room for RP JWKS caches.
const KeyRetention = time.Hour

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

// Ensure creates the first signing key if there is none. A lock keeps
// replicas starting together from each adding one.
func (k *Keys) Ensure(ctx context.Context) error {
	tx, err := k.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := k.q.WithTx(tx)
	if err := q.LockSigningKeys(ctx); err != nil {
		return err
	}
	keys, err := q.SigningKeys(ctx, keyRetention)
	if err != nil || len(keys) > 0 {
		return err
	}
	if err := add(ctx, q, k.keyring); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Rotate makes a new key current. The old ones retire by age (see
// KeyRetention); the hourly cleanup deletes them.
func (k *Keys) Rotate(ctx context.Context) error {
	return add(ctx, k.q, k.keyring)
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

func add(ctx context.Context, q *sqlc.Queries, keyring *crypt.Keyring) error {
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
	return q.InsertSigningKey(ctx, sqlc.InsertSigningKeyParams{Kid: kid, Sealed: sealed})
}

func keyAAD(kid string) []byte { return []byte("signing_key:" + kid) }
