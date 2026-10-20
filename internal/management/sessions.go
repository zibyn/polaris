package management

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

type Session struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind" enum:"browser,app" doc:"A browser Session signs in to any Application; an App Session is one Application's refresh token chain"`
	Application string     `json:"application" doc:"client_id of the Application the Session was started for"`
	AuthTime    time.Time  `json:"authTime"`
	AMR         []string   `json:"amr" nullable:"false"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	ExpiresAt   time.Time  `json:"expiresAt" doc:"When it ends if left idle"`
	EndedAt     *time.Time `json:"endedAt,omitempty" doc:"When it was ended: logout, an admin, or a reused refresh token"`
	Active      bool       `json:"active"`
}

type listSessionsOutput struct {
	Body struct {
		Sessions []Session `json:"sessions" nullable:"false" doc:"Newest activity first; ended and expired ones stay for 30 days"`
	}
}

func (s *Service) listSessions(ctx context.Context, in *struct {
	Sub string `path:"sub"`
}) (*listSessionsOutput, error) {
	if err := s.ensureUser(ctx, in.Sub); err != nil {
		return nil, err
	}
	rows, err := s.q.UserSessions(ctx, in.Sub)
	if err != nil {
		return nil, err
	}
	out := &listSessionsOutput{}
	out.Body.Sessions = []Session{}
	for _, r := range rows {
		sess := Session{
			ID: r.ID, Kind: "browser", Application: r.ClientID.String, AuthTime: r.AuthTime.Time, AMR: r.Amr,
			LastSeenAt: r.LastSeenAt.Time, ExpiresAt: r.ExpiresAt.Time, Active: r.Active,
		}
		if r.App {
			sess.Kind = "app"
		}
		if r.EndedAt.Valid {
			sess.EndedAt = &r.EndedAt.Time
		}
		out.Body.Sessions = append(out.Body.Sessions, sess)
	}
	return out, nil
}

func (s *Service) endSession(ctx context.Context, in *struct {
	Sub string `path:"sub"`
	ID  string `path:"id"`
}) (*struct{}, error) {
	n, err := s.q.EndUserSession(ctx, sqlc.EndUserSessionParams{ID: in.ID, UserID: in.Sub, By: ctx.Value(callerKey{}).(caller).sub})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, huma.Error404NotFound("no such live Session")
	}
	return nil, nil
}
