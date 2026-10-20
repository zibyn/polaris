// Package pow is the ALTCHA proof of work that sending a code requires: the
// browser (or the SDK) fetches a signed challenge, solves it, and sends the
// solution with the request. A solution is good once.
package pow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

const ErrUnsolved identity.Invalid = "人机验证未通过,请重试"

// ponytail: fixed difficulty, about a second in a phone browser; raise
// cost or the counter range if bots keep up.
const (
	algorithm = "PBKDF2/SHA-256"
	cost      = 1000
	ttl       = 10 * time.Minute // covers solving and filling in the form
)

var deriveKey = altcha.DeriveKeyPBKDF2()

type PoW struct {
	q      *sqlc.Queries
	secret string
}

func New(ctx context.Context, pool *pgxpool.Pool) (*PoW, error) {
	q := sqlc.New(pool)
	secret, err := q.PoWSecret(ctx)
	if err != nil {
		return nil, err
	}
	return &PoW{q: q, secret: secret}, nil
}

func (p *PoW) Challenge() (altcha.Challenge, error) {
	counter := 500 + rand.IntN(1000)
	expires := time.Now().Add(ttl)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:           algorithm,
		Cost:                cost,
		Counter:             &counter,
		DeriveKey:           deriveKey,
		ExpiresAt:           &expires,
		HMACSignatureSecret: p.secret,
	})
}

// ServeChallenge is the endpoint the widget fetches a challenge from.
func (p *PoW) ServeChallenge(w http.ResponseWriter, _ *http.Request) {
	ch, err := p.Challenge()
	if err != nil {
		slog.Error("pow challenge", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(ch)
}

// DeleteExpired forgets spent challenges past their expiry; run by the
// hourly cleanup.
func DeleteExpired(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteExpiredPoW(ctx)
}

// Verify checks payload, the widget's base64 JSON, and spends it.
func (p *PoW) Verify(ctx context.Context, payload string) error {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ErrUnsolved
	}
	var pl altcha.Payload
	if err := json.Unmarshal(raw, &pl); err != nil {
		return ErrUnsolved
	}
	if pl.Challenge.Parameters.ExpiresAt == 0 {
		return ErrUnsolved // would never expire
	}
	res, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:           pl.Challenge,
		Solution:            pl.Solution,
		DeriveKey:           deriveKey,
		HMACSignatureSecret: p.secret,
	})
	if err != nil || !res.Verified {
		return ErrUnsolved
	}
	n, err := p.q.SpendPoW(ctx, sqlc.SpendPoWParams{
		Signature: pl.Challenge.Signature,
		ExpiresAt: pgtype.Timestamptz{Time: time.Unix(pl.Challenge.Parameters.ExpiresAt, 0), Valid: true},
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUnsolved
	}
	return nil
}
