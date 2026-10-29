package oidcstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/oidc/goidc"
)

func TestJTIIsGoodOnce(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)

	if err := s.ConsumeJTI(ctx, "proof-1"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	err := s.ConsumeJTI(ctx, "proof-1")
	if err == nil {
		t.Fatal("replayed jti accepted")
	}
	// go-oidc lets ErrNotFound from the consumer through; a replay must not be one.
	if errors.Is(err, goidc.ErrNotFound) {
		t.Fatal("replay reported as ErrNotFound")
	}
	if err := s.ConsumeJTI(ctx, "proof-2"); err != nil {
		t.Fatalf("other jti: %v", err)
	}
}

func TestJTIConcurrentUseOneWins(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)

	const n = 8
	errs := make(chan error, n)
	var start sync.WaitGroup
	start.Add(1)
	for range n {
		go func() {
			start.Wait()
			errs <- s.ConsumeJTI(ctx, "same")
		}()
	}
	start.Done()
	ok := 0
	for range n {
		if <-errs == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d concurrent uses succeeded, want 1", ok, n)
	}
}

func TestJTIExpiresAndIsCleanedUp(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	s := New(pool, keyring)
	s.JTITTL = -time.Second // its JWT has already expired
	if err := s.ConsumeJTI(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	s.JTITTL = time.Hour
	if err := s.ConsumeJTI(ctx, "fresh"); err != nil {
		t.Fatal(err)
	}

	if err := DeleteExpired(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := pool.Query(ctx, `SELECT jti FROM oidc_jtis`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			t.Fatal(err)
		}
		left = append(left, j)
	}
	if len(left) != 1 || left[0] != "fresh" {
		t.Fatalf("jtis after cleanup = %v, want [fresh]", left)
	}
}
