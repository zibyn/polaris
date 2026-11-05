package db

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrConflict is an optimistic write that found what it read had changed
// meanwhile (ADR 0030): a conditional UPDATE or INSERT that touched no row.
var ErrConflict = errors.New("db: changed since read")

// Retry runs fn in a transaction, and again from the top while it returns
// ErrConflict, at most three times in all; then the conflict is the error.
func Retry(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	for i := 1; ; i++ {
		err := pgx.BeginFunc(ctx, pool, fn)
		if !errors.Is(err, ErrConflict) || i == 3 {
			return err
		}
	}
}

// Serializable runs fn in a SERIALIZABLE transaction, and again from the
// top while PostgreSQL refuses it for a serialization failure, at most ten
// times in all. It keeps an invariant across rows (ADR 0030): of two
// transactions that each checked it and then broke it together, one is
// refused and, run again, sees the other's write. Each retry first waits a
// random while, so two refused at once do not collide again.
func Serializable(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	for i := 1; ; i++ {
		err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, fn)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" || i == 10 {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(rand.N(time.Duration(i) * 5 * time.Millisecond)):
		}
	}
}
