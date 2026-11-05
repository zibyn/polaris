package webhook

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// A delivery's facts become the documented payload (docs/spec/protocol.md#webhook):
// {"type", "timestamp", "data"}, the timestamp RFC 3339 in UTC, changed only
// on user.updated.
func TestEventBody(t *testing.T) {
	at := pgtype.Timestamptz{Time: time.Date(2026, 11, 5, 9, 2, 3, 456, time.FixedZone("CST", 8*3600)), Valid: true}
	for facts, want := range map[string]string{
		`{"type": "user.updated", "sub": "ALICE", "changed": ["phone"]}`: `{"type":"user.updated","timestamp":"2026-11-05T01:02:03Z","data":{"sub":"ALICE","changed":["phone"]}}`,
		`{"type": "user.disabled", "sub": "ALICE"}`:                      `{"type":"user.disabled","timestamp":"2026-11-05T01:02:03Z","data":{"sub":"ALICE"}}`,
	} {
		got, err := eventBody(sqlc.ClaimDeliveriesRow{Payload: []byte(facts), CreatedAt: at})
		if err != nil || string(got) != want {
			t.Errorf("%s:\n got %s %v\nwant %s", facts, got, err, want)
		}
	}
}
