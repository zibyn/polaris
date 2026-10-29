package db

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// hook is one expected webhook delivery to the Application "hooked".
type hook struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func updated(sub string, changed ...string) hook {
	c := make([]any, len(changed))
	for i, k := range changed {
		c[i] = k
	}
	return hook{"user.updated", map[string]any{"sub": sub, "changed": c}}
}

func bare(typ, sub string) hook { return hook{typ, map[string]any{"sub": sub}} }

// userEventCases are, for every query that calls user_event(), a write that
// changes something (exactly the expected deliveries) and one that changes
// nothing (none) — ADR 0026. Plus two writes that must never queue.
var userEventCases = []struct {
	query, name string
	setup       string // SQL run first, in the same transaction
	run         func(context.Context, *sqlc.Queries) error
	want        []hook
}{
	{"BindIdentifier", "binds", "", func(ctx context.Context, q *sqlc.Queries) error {
		return q.BindIdentifier(ctx, sqlc.BindIdentifierParams{UserID: "ALICE", Kind: "phone", Value: "+8613800138000"})
	}, []hook{updated("ALICE", "phone")}},
	// BindIdentifier has no "unchanged" form: binding a kind the User already
	// has is a unique violation, which rolls the whole write back.

	{"ReplaceIdentifier", "new value", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.ReplaceIdentifier(ctx, sqlc.ReplaceIdentifierParams{UserID: "ALICE", Kind: "email", Value: "alice@new.example", By: "OWNER"})
		return err
	}, []hook{updated("ALICE", "email")}},
	{"ReplaceIdentifier", "same value", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.ReplaceIdentifier(ctx, sqlc.ReplaceIdentifierParams{UserID: "ALICE", Kind: "email", Value: "alice@example.com", By: "OWNER"})
		return err
	}, nil},

	{"RemoveIdentifier", "held", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.RemoveIdentifier(ctx, sqlc.RemoveIdentifierParams{UserID: "ALICE", Kind: "email"})
		return err
	}, []hook{updated("ALICE", "email")}},
	{"RemoveIdentifier", "not held", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.RemoveIdentifier(ctx, sqlc.RemoveIdentifierParams{UserID: "ALICE", Kind: "phone"})
		return err
	}, nil},

	{"SetNickname", "new nickname", "UPDATE users SET nickname = 'A' WHERE id = 'ALICE'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetNickname(ctx, sqlc.SetNicknameParams{UserID: "ALICE", Nickname: "B"})
		return err
	}, []hook{updated("ALICE", "profile")}},
	{"SetNickname", "same nickname", "UPDATE users SET nickname = 'A' WHERE id = 'ALICE'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetNickname(ctx, sqlc.SetNicknameParams{UserID: "ALICE", Nickname: "A"})
		return err
	}, nil},
	{"SetNickname", "clear when none", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetNickname(ctx, sqlc.SetNicknameParams{UserID: "ALICE", Nickname: ""})
		return err
	}, nil},

	{"SetAvatar", "new avatar", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetAvatar(ctx, sqlc.SetAvatarParams{UserID: "ALICE", Avatar: "k1"})
		return err
	}, []hook{updated("ALICE", "profile")}},
	{"SetAvatar", "same avatar", "UPDATE users SET avatar = 'k1' WHERE id = 'ALICE'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetAvatar(ctx, sqlc.SetAvatarParams{UserID: "ALICE", Avatar: "k1"})
		return err
	}, nil},

	{"SetUserRoles", "other Roles", "", func(ctx context.Context, q *sqlc.Queries) error {
		return q.SetUserRoles(ctx, sqlc.SetUserRolesParams{UserID: "ALICE", Api: "track", Roles: []string{"viewer", "editor"}, By: "OWNER"})
	}, []hook{updated("ALICE", "roles")}},
	{"SetUserRoles", "fewer Roles", "", func(ctx context.Context, q *sqlc.Queries) error {
		return q.SetUserRoles(ctx, sqlc.SetUserRolesParams{UserID: "ALICE", Api: "track", Roles: []string{}, By: "OWNER"})
	}, []hook{updated("ALICE", "roles")}},
	{"SetUserRoles", "same Roles", "", func(ctx context.Context, q *sqlc.Queries) error {
		return q.SetUserRoles(ctx, sqlc.SetUserRolesParams{UserID: "ALICE", Api: "track", Roles: []string{"viewer"}, By: "OWNER"})
	}, nil},

	{"DeleteAPI", "held", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteAPI(ctx, sqlc.DeleteAPIParams{Identifier: "track", Force: true})
		return err
	}, []hook{updated("ALICE", "roles"), updated("BOB", "roles")}},
	{"DeleteAPI", "held by no one", "DELETE FROM user_roles WHERE api = 'track'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteAPI(ctx, sqlc.DeleteAPIParams{Identifier: "track", Force: true})
		return err
	}, nil},

	{"DeleteRole", "held", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteRole(ctx, sqlc.DeleteRoleParams{Api: "track", Key: "editor", Force: true})
		return err
	}, []hook{updated("BOB", "roles")}},
	{"DeleteRole", "held by no one", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteRole(ctx, sqlc.DeleteRoleParams{Api: "track", Key: "unused", Force: true})
		return err
	}, nil},

	{"SetUserDisabled", "disable", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: "ALICE", Disabled: true, By: "OWNER"})
		return err
	}, []hook{bare("user.disabled", "ALICE")}},
	{"SetUserDisabled", "enable", "UPDATE users SET disabled_at = now() WHERE id = 'ALICE'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: "ALICE", Disabled: false, By: "OWNER"})
		return err
	}, []hook{bare("user.enabled", "ALICE")}},
	{"SetUserDisabled", "already enabled", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: "ALICE", Disabled: false, By: "OWNER"})
		return err
	}, nil},
	{"SetUserDisabled", "already disabled", "UPDATE users SET disabled_at = now() WHERE id = 'ALICE'", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: "ALICE", Disabled: true, By: "OWNER"})
		return err
	}, nil},

	{"DeleteUser", "exists", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: "ALICE", By: "OWNER"})
		return err
	}, []hook{bare("user.deleted", "ALICE")}},
	{"DeleteUser", "no such User", "", func(ctx context.Context, q *sqlc.Queries) error {
		_, err := q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: "NOBODY", By: "OWNER"})
		return err
	}, nil},

	// Sign-up: a new User, with the default Roles and an Identifier, is not
	// an update of anyone.
	{"CreateUser", "with a default Role", "UPDATE roles SET default_role = true WHERE api = 'track' AND key = 'viewer'", func(ctx context.Context, q *sqlc.Queries) error {
		return q.CreateUser(ctx, "CAROL")
	}, nil},
	{"AddIdentifier", "on sign-up", "INSERT INTO users (id) VALUES ('CAROL')", func(ctx context.Context, q *sqlc.Queries) error {
		return q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: "CAROL", Kind: "email", Value: "carol@example.com"})
	}, nil},
}

// Each case runs in its own rolled-back transaction over the same world:
// Applications "hooked" (with a webhook) and "plain"; ALICE with an email
// and Role viewer on API track; BOB with Role editor.
func TestUserEventQueries(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (client_id, name, type, webhook_url, webhook_secret) VALUES
			('hooked', 'hooked', 'public', 'https://rp.example/hook', 'x'),
			('plain', 'plain', 'public', NULL, NULL);
		INSERT INTO apis (identifier, name) VALUES ('track', 'Track');
		INSERT INTO roles (api, key, name) VALUES ('track', 'viewer', 'V'), ('track', 'editor', 'E'), ('track', 'unused', 'U');
		INSERT INTO users (id) VALUES ('ALICE'), ('BOB');
		INSERT INTO identifiers (user_id, kind, value) VALUES ('ALICE', 'email', 'alice@example.com');
		INSERT INTO user_roles (user_id, api, role) VALUES ('ALICE', 'track', 'viewer'), ('BOB', 'track', 'editor');
	`); err != nil {
		t.Fatal(err)
	}

	for _, c := range userEventCases {
		t.Run(c.query+"/"+c.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if c.setup != "" {
				if _, err := tx.Exec(ctx, c.setup); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.run(ctx, sqlc.New(tx)); err != nil {
				t.Fatal(err)
			}
			got := queued(t, tx)
			if len(got) != len(c.want) {
				t.Fatalf("queued %+v, want %+v", got, c.want)
			}
			for i, g := range got {
				gj, _ := json.Marshal(g)
				wj, _ := json.Marshal(c.want[i])
				if string(gj) != string(wj) {
					t.Errorf("delivery %d: %s, want %s", i, gj, wj)
				}
			}
		})
	}
}

// queued reads the webhook deliveries in tx, ordered by sub, checking each
// goes to "hooked" with a timestamp, and returns them without it.
func queued(t *testing.T, tx pgx.Tx) []hook {
	t.Helper()
	rows, err := tx.Query(context.Background(), `
		SELECT client_id, payload FROM webhook_deliveries WHERE kind = 'webhook' ORDER BY payload->'data'->>'sub'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []hook
	for rows.Next() {
		var to string
		var p map[string]any
		if err := rows.Scan(&to, &p); err != nil {
			t.Fatal(err)
		}
		if to != "hooked" || p["timestamp"] == "" || p["timestamp"] == nil || len(p) != 3 {
			t.Errorf("delivery to %s: %v", to, p)
		}
		h := hook{Type: p["type"].(string)}
		h.Data, _ = p["data"].(map[string]any)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every query that calls user_event() must be in userEventCases with a write
// that queues something, so a new one cannot go untested.
func TestUserEventQueriesAllListed(t *testing.T) {
	files, err := filepath.Glob("queries/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("no queries", err)
	}
	var calling []string
	name := regexp.MustCompile(`(?m)^-- name: (\w+)`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		ms := name.FindAllStringSubmatchIndex(src, -1)
		for i, m := range ms {
			end := len(src)
			if i+1 < len(ms) {
				end = ms[i+1][0]
			}
			if strings.Contains(src[m[0]:end], "user_event(") {
				calling = append(calling, src[m[2]:m[3]])
			}
		}
	}
	var listed []string
	for _, c := range userEventCases {
		if len(c.want) > 0 && !slices.Contains(listed, c.query) {
			listed = append(listed, c.query)
		}
	}
	slices.Sort(calling)
	slices.Sort(listed)
	if !slices.Equal(calling, listed) {
		t.Errorf("queries calling user_event(): %v; listed with an event: %v", calling, listed)
	}
}
