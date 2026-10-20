// Package dbtest gives tests their own empty database.
package dbtest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fresh creates an empty database named after the test on
// POLARIS_TEST_DATABASE_URL's server, or skips the test when it is unset.
func Fresh(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("POLARIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("POLARIS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx) //nolint:errcheck
	// t.Name() is unique inside one test binary, not across them: `go test
	// ./...` runs packages in parallel against the same server, so two tests
	// with the same name would drop each other's database (DROP ... WITH
	// FORCE). Prefix the package directory.
	_, file, _, _ := runtime.Caller(1)
	name := "t_" + filepath.Base(filepath.Dir(file)) + "_" + t.Name()
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
