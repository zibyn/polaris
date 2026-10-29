package management_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zibyn/polaris/internal/oidcstore"
)

// delivery is one queued webhook delivery.
type delivery struct {
	To        string
	Type      string
	Timestamp string
	Data      map[string]any
}

// hooked adds Applications "hooked" (with a webhook) and "plain" (without).
func (e *env) hooked() {
	e.t.Helper()
	ctx := context.Background()
	for _, id := range []string{"hooked", "plain"} {
		if err := oidcstore.CreateApplication(ctx, e.pool, oidcstore.Application{ClientID: id, Name: id}); err != nil {
			e.t.Fatal(err)
		}
	}
	if _, err := e.pool.Exec(ctx, "UPDATE applications SET webhook_url = 'https://rp.example/hook', webhook_secret = 'x' WHERE client_id = 'hooked'"); err != nil {
		e.t.Fatal(err)
	}
}

// deliveries takes every queued delivery, oldest first.
func (e *env) deliveries() []delivery {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "DELETE FROM webhook_deliveries RETURNING client_id, payload")
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []delivery
	for rows.Next() {
		var d delivery
		var payload []byte
		if err := rows.Scan(&d.To, &payload); err != nil {
			e.t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &d); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// queued checks the deliveries since the last call: one per event, to the
// hooked Application only, carrying only sub (and changed for user.updated).
func (e *env) queued(what string, want ...delivery) {
	e.t.Helper()
	got := e.deliveries()
	if len(got) != len(want) {
		e.t.Fatalf("%s: got %d deliveries %+v, want %d", what, len(got), got, len(want))
	}
	for i, d := range got {
		w := want[i]
		if d.To != "hooked" || d.Type != w.Type || d.Timestamp == "" || d.Data["sub"] != w.Data["sub"] || len(d.Data) != len(w.Data) {
			e.t.Errorf("%s: delivery %+v, want %+v", what, d, w)
		}
		if w.Data["changed"] != nil {
			g, _ := json.Marshal(d.Data["changed"])
			x, _ := json.Marshal(w.Data["changed"])
			if string(g) != string(x) {
				e.t.Errorf("%s: changed %s, want %s", what, g, x)
			}
		}
	}
}

func event(typ, sub string, changed ...string) delivery {
	d := delivery{Type: typ, Data: map[string]any{"sub": sub}}
	if changed != nil {
		d.Data["changed"] = changed
	}
	return d
}

func TestWebhookUserDisabledAndEnabled(t *testing.T) {
	e := start(t)
	e.hooked()
	e.user("ALICE", nil, "email:alice@example.com")
	owner := e.token(e.owner, nil)

	e.call("POST", owner, "/users/ALICE/disable", nil, nil)
	e.queued("disable", event("user.disabled", "ALICE"))
	e.call("POST", owner, "/users/ALICE/disable", nil, nil)
	e.queued("disable again")
	e.call("POST", owner, "/users/ALICE/enable", nil, nil)
	e.queued("enable", event("user.enabled", "ALICE"))
	e.call("POST", owner, "/users/ALICE/enable", nil, nil)
	e.queued("enable again")
}

func TestWebhookAdminChangesIdentifiers(t *testing.T) {
	e := start(t)
	e.hooked()
	e.user("ALICE", nil, "email:alice@example.com")
	owner := e.token(e.owner, nil)
	put := func(kind, value string) {
		t.Helper()
		if code := e.call("PUT", owner, "/users/ALICE/identifiers/"+kind, map[string]string{"value": value}, nil); code != 204 {
			t.Fatalf("put %s: %d", kind, code)
		}
	}

	put("email", "alice@new.example")
	e.queued("replace email", event("user.updated", "ALICE", "email"))
	put("phone", "13800001111")
	e.queued("add phone", event("user.updated", "ALICE", "phone"))
	put("username", "alice")
	e.queued("add username", event("user.updated", "ALICE", "username"))
	e.call("PUT", owner, "/users/ALICE/identifiers/email", map[string]string{"value": "nope"}, nil)
	e.queued("invalid email")
}

func TestWebhookRoles(t *testing.T) {
	e := start(t)
	e.hooked()
	e.trackAPI()
	e.user("ALICE", nil)
	e.user("BOB", nil)
	owner := e.token(e.owner, nil)
	set := func(sub string, roles ...string) {
		t.Helper()
		if code := e.call("PUT", owner, "/users/"+sub+"/roles", map[string]any{"api": track, "roles": append([]string{}, roles...)}, nil); code != 204 {
			t.Fatalf("set roles: %d", code)
		}
	}

	set("ALICE", "viewer", "editor")
	e.queued("assign", event("user.updated", "ALICE", "roles"))
	set("ALICE", "viewer", "editor")
	e.queued("same Roles again")
	set("ALICE", "editor")
	e.queued("take one away", event("user.updated", "ALICE", "roles"))
	set("BOB", "editor")
	e.queued("assign BOB", event("user.updated", "BOB", "roles"))

	// Changing only Permissions tells nobody.
	if code := e.call("PUT", owner, apiPath(track)+"/permissions/track:read", map[string]any{"name": "r"}, nil); code != 204 {
		t.Fatalf("put Permission: %d", code)
	}
	if code := e.call("PUT", owner, apiPath(track)+"/roles/editor", map[string]any{"name": "E", "permissions": []string{"track:read"}}, nil); code != 204 {
		t.Fatalf("put Role: %d", code)
	}
	if code := e.call("DELETE", owner, apiPath(track)+"/permissions/track:read", nil, nil); code != 204 {
		t.Fatalf("delete Permission: %d", code)
	}
	e.queued("Permissions only")

	// Force-deleting a Role tells each User who held it.
	if code := e.call("DELETE", owner, apiPath(track)+"/roles/editor", nil, nil); code != 409 {
		t.Fatalf("delete held Role unconfirmed: %d", code)
	}
	e.queued("refused delete")
	if code := e.call("DELETE", owner, apiPath(track)+"/roles/editor?force=true", nil, nil); code != 204 {
		t.Fatalf("force delete Role: %d", code)
	}
	got := e.deliveries()
	if len(got) != 2 || got[0].Data["sub"] == got[1].Data["sub"] {
		t.Fatalf("force delete Role: %+v", got)
	}
	for _, d := range got {
		if d.To != "hooked" || d.Type != "user.updated" || (d.Data["sub"] != "ALICE" && d.Data["sub"] != "BOB") || len(d.Data) != 2 {
			t.Errorf("force delete Role: %+v", d)
		}
	}

	// So does force-deleting an API.
	set("ALICE", "viewer")
	e.deliveries()
	if code := e.call("DELETE", owner, apiPath(track)+"?force=true", nil, nil); code != 204 {
		t.Fatalf("force delete API: %d", code)
	}
	e.queued("force delete API", event("user.updated", "ALICE", "roles"))
}
