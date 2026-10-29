package management

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Every write audits itself, in the transaction that makes the change
// (ADR 0025); TestEveryWriteIsAudited holds each one to it.

type AuditEvent struct {
	ID     int64          `json:"id"`
	At     time.Time      `json:"at"`
	Event  string         `json:"event"`
	Sub    string         `json:"sub,omitempty" doc:"The User it is about"`
	User   string         `json:"user,omitempty" doc:"sub's primary Identifier; absent once the User is deleted"`
	ByUser string         `json:"byUser,omitempty" doc:"detail.by's primary Identifier; absent once that User is deleted"`
	Detail map[string]any `json:"detail" doc:"by is the User or M2M Application (byType) who did it"`
}

type listAuditInput struct {
	Event  string    `query:"event"`
	Sub    string    `query:"sub" doc:"Events about this User or done by them"`
	Since  time.Time `query:"since" doc:"From this time on"`
	Until  time.Time `query:"until" doc:"Before this time"`
	Before int64     `query:"before" doc:"Events older than this id: the next page"`
	Limit  int32     `query:"limit" default:"50" minimum:"1" maximum:"200"`
}

type listAuditOutput struct {
	Body struct {
		Events []AuditEvent `json:"events" nullable:"false" doc:"Newest first"`
	}
}

func (s *Service) listAudit(ctx context.Context, in *listAuditInput) (*listAuditOutput, error) {
	ts := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()} }
	rows, err := s.q.ListAudit(ctx, sqlc.ListAuditParams{
		Event: in.Event, Sub: in.Sub, Since: ts(in.Since), Until: ts(in.Until), Before: in.Before, Lim: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := &listAuditOutput{}
	out.Body.Events = []AuditEvent{}
	for _, r := range rows {
		ev := AuditEvent{ID: r.ID, At: r.At.Time, Event: r.Event, Sub: r.Sub, User: r.UserIdentifier, ByUser: r.ByIdentifier}
		if err := json.Unmarshal(r.Detail, &ev.Detail); err != nil {
			return nil, err
		}
		out.Body.Events = append(out.Body.Events, ev)
	}
	return out, nil
}

type overviewOutput struct {
	Body struct {
		Users          int64 `json:"users"`
		LoginsToday    int64 `json:"loginsToday" doc:"Sessions signed in to since midnight"`
		LiveSessions   int64 `json:"liveSessions"`
		Applications   int64 `json:"applications"`
		SendsLastDay   int64 `json:"sendsLastDay" doc:"Codes sent in the last 24 hours, which the daily limit caps"`
		DailySendLimit int32 `json:"dailySendLimit"`
	}
}

func (s *Service) overview(ctx context.Context, _ *struct{}) (*overviewOutput, error) {
	r, err := s.q.Overview(ctx)
	if err != nil {
		return nil, err
	}
	out := &overviewOutput{}
	b := &out.Body
	b.Users, b.LoginsToday, b.LiveSessions, b.Applications, b.SendsLastDay, b.DailySendLimit =
		r.Users, r.LoginsToday, r.LiveSessions, r.Applications, r.SendsLastDay, r.DailySendLimit
	return out, nil
}
