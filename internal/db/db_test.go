package db

import (
	"context"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/zibyn/stars-auth/internal/db/dbtest"
	"golang.org/x/sync/errgroup"
)

func TestMigrateConcurrentReplicas(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	// Upgrade an already-migrated database (a fresh one is accidentally
	// serialised by goose creating its version table).
	fsys := fstest.MapFS{"00001_a.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")}}
	if err := migrate(ctx, pool, fsys); err != nil {
		t.Fatal(err)
	}
	// Slow and non-idempotent: a second runner would fail or double-record.
	fsys["00002_slow.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT pg_sleep(0.3);\nCREATE TABLE once (id int);\n")}

	var g errgroup.Group
	for range 4 {
		g.Go(func() error { return migrate(ctx, pool, fsys) })
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM goose_db_version WHERE version_id = 2`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("migration recorded %d times, want 1", rows)
	}
}

func TestMigrateEmbedded(t *testing.T) {
	pool := dbtest.Fresh(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
}

// The password login switch went from three values to two (ADR 0017). A
// stored 'admins' must fold to 'on': folding it to 'off' would lock out every
// owner who signs in with a username and a password alone, at the moment they
// upgrade. 'admins' then stops being a value the column accepts.
func TestPasswordLoginThreeStatesFoldToTwo(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := migrate(ctx, pool, before24(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE settings SET password_login = 'admins'"); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := pool.QueryRow(ctx, "SELECT password_login FROM settings").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "on" {
		t.Errorf("stored 'admins' became %q, want on", got)
	}
	if _, err := pool.Exec(ctx, "UPDATE settings SET password_login = 'admins'"); err == nil {
		t.Error("'admins' is still accepted")
	}
}

// A fresh instance defaults to on, so a deployment with no Channel and no
// Provider can still finish 首次引导 (ADR 0006).
func TestFreshInstanceDefaultsToPasswordLoginOn(t *testing.T) {
	pool := dbtest.Fresh(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := pool.QueryRow(context.Background(), "SELECT password_login FROM settings").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "on" {
		t.Errorf("default = %q, want on", got)
	}
}

// before24 is the embedded migrations as they stood before 00024, so a test
// can start an instance in the old three-value shape.
func before24(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{}
	for _, e := range entries {
		n, err := strconv.ParseInt(strings.SplitN(e.Name(), "_", 2)[0], 10, 64)
		if err != nil || n >= 24 {
			continue
		}
		b, err := fs.ReadFile(sub, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = &fstest.MapFile{Data: b}
	}
	return files
}
