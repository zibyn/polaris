package management

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
)

// selfAudited are the writes that audit themselves, in the same
// transaction and with more detail; auditWrite audits the rest.
var selfAudited = map[string]bool{
	"end-session": true, "disable-user": true, "enable-user": true, "delete-user": true, "create-user": true,
	"replace-identifier": true, "set-user-roles": true, "put-settings": true, "rotate-signing-keys": true,
	"reset-two-factor": true, "create-provider": true, "unbind-external-identity": true,
	"remove-user-passkey": true, "set-application-roles": true,
	"send-invite": true, "revoke-invite": true,
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// auditWrite records a successful Management API write by sub as an event
// named after its operation, with its path and query parameters.
// ponytail: written after the response, so a PG failure here loses the
// event (logged); move into each handler's transaction if that matters.
func (s *Service) auditWrite(ctx huma.Context, by string) {
	op := ctx.Operation()
	if op.Method == http.MethodGet || selfAudited[op.OperationID] || ctx.Status() >= 300 {
		return
	}
	detail := map[string]string{}
	u := ctx.URL()
	for k, v := range u.Query() {
		detail[k] = v[0]
	}
	for _, m := range pathParam.FindAllStringSubmatch(op.Path, -1) {
		detail[m[1]] = ctx.Param(m[1])
	}
	detail["by"] = by
	sub := pgtype.Text{String: detail["sub"], Valid: detail["sub"] != ""}
	raw, _ := json.Marshal(detail)
	if err := s.q.Audit(context.WithoutCancel(ctx.Context()), sqlc.AuditParams{Event: op.OperationID, Sub: sub, Detail: raw}); err != nil {
		slog.Error("audit", "event", op.OperationID, "err", err)
	}
}

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
