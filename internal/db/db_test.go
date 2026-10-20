package db

import (
	"context"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/zibyn/polaris/internal/db/dbtest"
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

// The password login switch went from three values to two (ADR 0017). Both
// stored 'admins' and stored 'all' must fold to 'on': folding either to 'off'
// would lock out every owner who signs in with a username and a password
// alone, at the moment they upgrade. Neither then stops being accepted.
func TestPasswordLoginThreeStatesFoldToTwo(t *testing.T) {
	ctx := context.Background()
	for _, old := range []string{"admins", "all"} {
		t.Run(old, func(t *testing.T) {
			pool := dbtest.Fresh(t)
			if err := migrate(ctx, pool, before24(t)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "UPDATE settings SET password_login = $1", old); err != nil {
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
				t.Errorf("stored %q became %q, want on", old, got)
			}
			if _, err := pool.Exec(ctx, "UPDATE settings SET password_login = $1", old); err == nil {
				t.Errorf("%q is still accepted", old)
			}
		})
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

// 待激活 is a new User status (ADR 0016). A User created before it is active:
// the column's default has to say so, or every existing User would read as
// 待激活 and be stopped at a password step they cannot pass.
func TestPendingStatusDefaultsToActive(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := migrate(ctx, pool, before25(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (id) VALUES ('OLD')"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pool.QueryRow(ctx, "SELECT status FROM users WHERE id = 'OLD'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Errorf("an existing User is %q, want active", status)
	}
	// And the column only accepts the two states.
	if _, err := pool.Exec(ctx, "UPDATE users SET status = 'nope'"); err == nil {
		t.Error("an unknown status is accepted")
	}
}

// before25 is the embedded migrations as they stood before 00025, so a test
// can start an instance without the 待激活 status column.
func before25(t *testing.T) fs.FS {
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
		if err != nil || n >= 25 {
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

// The built-in Applications and APIs use Polaris identifiers; roles and
// permissions hang off the API identifier they belong to.
func TestBuiltinIdentifiers(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	var apps, apis, roles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM applications
		WHERE client_id IN ('polaris-console', 'polaris-account') AND builtin`).Scan(&apps); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM apis
		WHERE identifier IN ('urn:polaris:management-api', 'urn:polaris:account-api') AND builtin`).Scan(&apis); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles
		WHERE api = 'urn:polaris:management-api'`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if apps != 2 || apis != 2 || roles != 3 {
		t.Fatalf("applications=%d apis=%d roles=%d, want 2 2 3", apps, apis, roles)
	}
}
