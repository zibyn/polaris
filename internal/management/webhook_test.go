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
	rows, err := e.pool.Query(context.Background(), "DELETE FROM webhook_deliveries WHERE kind = 'webhook' RETURNING client_id, payload")
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

// Wiring only: which writes queue what is TestUserEventQueries in internal/db.
func TestWebhookUserDisabled(t *testing.T) {
	e := start(t)
	e.hooked()
	e.user("ALICE", nil, "email:alice@example.com")

	e.call("POST", e.token(e.owner, nil), "/users/ALICE/disable", nil, nil)
	e.queued("disable", event("user.disabled", "ALICE"))
}
