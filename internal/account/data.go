package account

import (
	"context"
	"encoding/json"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

type Session struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind" enum:"browser,app"`
	Application string     `json:"application" doc:"Name of the Application the Session was started for"`
	AuthTime    time.Time  `json:"authTime"`
	AMR         []string   `json:"amr" nullable:"false"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	EndedAt     *time.Time `json:"endedAt,omitempty"`
	Active      bool       `json:"active"`
	Current     bool       `json:"current" doc:"The Session this request comes from"`
	IP          string     `json:"ip" doc:"The client IP it was last used from; empty for a Session from before IPs were kept"`
	UserAgent   string     `json:"userAgent" doc:"The User-Agent it was last used with, cut to 512 bytes; may be empty"`
}

type listSessionsOutput struct {
	Body struct {
		Sessions []Session `json:"sessions" nullable:"false" doc:"Newest activity first; ended ones stay for 30 days"`
	}
}

func (s *Service) listSessions(ctx context.Context, _ *struct{}) (*listSessionsOutput, error) {
	out := &listSessionsOutput{}
	var err error
	out.Body.Sessions, err = s.sessions(ctx)
	return out, err
}

func (s *Service) sessions(ctx context.Context) ([]Session, error) {
	c := callerOf(ctx)
	rows, err := s.q.UserSessions(ctx, c.sub)
	if err != nil {
		return nil, err
	}
	out := []Session{}
	for _, r := range rows {
		sess := Session{
			ID: r.ID, Kind: "browser", Application: r.ApplicationName, AuthTime: r.AuthTime.Time, AMR: r.Amr,
			LastSeenAt: r.LastSeenAt.Time, IP: r.Ip.String, UserAgent: r.UserAgent.String, Active: r.Active, Current: r.ID == c.session,
		}
		if r.App {
			sess.Kind = "app"
		}
		if r.EndedAt.Valid {
			sess.EndedAt = &r.EndedAt.Time
		}
		out = append(out, sess)
	}
	return out, nil
}

func (s *Service) endSession(ctx context.Context, in *struct {
	ID string `path:"id"`
}) (*struct{}, error) {
	sub := callerOf(ctx).sub
	n, err := s.q.EndUserSession(ctx, sqlc.EndUserSessionParams{ID: in.ID, UserID: sub, By: sub})
	if err == nil && n == 0 {
		err = huma.Error404NotFound("no such live Session")
	}
	return nil, err
}

type Consent struct {
	Version     string    `json:"version"`
	Application string    `json:"application" doc:"client_id of the Application it was given through"`
	At          time.Time `json:"at"`
}

type AuditEvent struct {
	At     time.Time       `json:"at"`
	Event  string          `json:"event"`
	Detail json.RawMessage `json:"detail"`
}

// BoundProvider is an External Identity as the export shows it: only the
// Provider's name and when it was bound.
type BoundProvider struct {
	Provider string    `json:"provider" doc:"The Provider's name"`
	BoundAt  time.Time `json:"boundAt"`
}

type exportOutput struct {
	ContentDisposition string `header:"Content-Disposition"`
	Body               struct {
		Sub                string          `json:"sub"`
		CreatedAt          time.Time       `json:"createdAt"`
		Identifiers        []Identifier    `json:"identifiers" nullable:"false"`
		ExternalIdentities []BoundProvider `json:"externalIdentities" nullable:"false"`
		Credentials        struct {
			Password  bool      `json:"password" doc:"Whether a password is set; never the password"`
			TwoFactor TwoFactor `json:"twoFactor" doc:"Never the TOTP secret or recovery codes"`
		} `json:"credentials"`
		Sessions    []Session    `json:"sessions" nullable:"false"`
		Consents    []Consent    `json:"consents" nullable:"false"`
		AuditEvents []AuditEvent `json:"auditEvents" nullable:"false"`
	}
}

// export is the User's personal data (docs/spec/security-compliance.md#个人信息导出).
func (s *Service) export(ctx context.Context, _ *struct{}) (*exportOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	sub := callerOf(ctx).sub
	u, err := s.q.AccountUser(ctx, sub)
	if err != nil {
		return nil, err
	}
	out := &exportOutput{ContentDisposition: `attachment; filename="polaris-` + sub + `.json"`}
	b := &out.Body
	b.Sub, b.CreatedAt, b.Credentials.Password, b.Credentials.TwoFactor = sub, u.CreatedAt.Time, u.HasPassword, twoFactorOf(u)
	b.ExternalIdentities, b.Consents, b.AuditEvents = []BoundProvider{}, []Consent{}, []AuditEvent{}
	if err := json.Unmarshal(u.Identifiers, &b.Identifiers); err != nil {
		return nil, err
	}
	ext, err := s.externalIdentities(ctx, sub)
	if err != nil {
		return nil, err
	}
	for _, x := range ext {
		b.ExternalIdentities = append(b.ExternalIdentities, BoundProvider{Provider: x.Name, BoundAt: x.BoundAt})
	}
	if b.Sessions, err = s.sessions(ctx); err != nil {
		return nil, err
	}
	consents, err := s.q.UserConsents(ctx, sub)
	if err != nil {
		return nil, err
	}
	for _, c := range consents {
		b.Consents = append(b.Consents, Consent{Version: c.Version, Application: c.ClientID, At: c.At.Time})
	}
	events, err := s.q.UserAudit(ctx, pgtype.Text{String: sub, Valid: true})
	if err != nil {
		return nil, err
	}
	for _, e := range events {
		b.AuditEvents = append(b.AuditEvents, AuditEvent{At: e.At.Time, Event: e.Event, Detail: e.Detail})
	}
	return out, nil
}
