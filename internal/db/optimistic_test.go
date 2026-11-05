package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
)

func TestRetry(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	runs := 0
	conflictTwice := func(pgx.Tx) error {
		if runs++; runs < 3 {
			return db.ErrConflict
		}
		return nil
	}
	if err := db.Retry(ctx, pool, conflictTwice); err != nil || runs != 3 {
		t.Errorf("two conflicts then success: %v after %d runs", err, runs)
	}
	runs = 0
	always := func(pgx.Tx) error { runs++; return db.ErrConflict }
	if err := db.Retry(ctx, pool, always); !errors.Is(err, db.ErrConflict) || runs != 3 {
		t.Errorf("always conflicting: %v after %d runs", err, runs)
	}
	runs = 0
	other := errors.New("other")
	if err := db.Retry(ctx, pool, func(pgx.Tx) error { runs++; return other }); err != other || runs != 1 {
		t.Errorf("another error is not retried: %v after %d runs", err, runs)
	}
}
