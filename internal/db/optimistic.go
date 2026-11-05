package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
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
