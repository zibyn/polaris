package provider

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

const (
	// ErrTaken: the External Identity is another User's (ADR 0003).
	ErrTaken         identity.Invalid = "这个外部账号已绑定其他账号,请先在那边解绑或注销"
	ErrBoundAnother  identity.Invalid = "已绑定这个外部登录方式的另一个账号,请先解绑"
	ErrNotYours      identity.Invalid = "这不是你绑定的外部账号"
	ErrNotAfreshAuth identity.Invalid = "请在外部登录页重新登录后再试"
)

// BeginAccount starts a redirect from the account center to the enabled
// Provider id, for the Session session of User userID: to bind the External
// Identity it gives, or with reauth, to reauthenticate the Session with the
// one bound. A reauthentication asks the Provider to sign the User in
// afresh (OIDC Core §3.1.2.1 prompt=login, max_age=0), where it is a
// Provider that can be asked.
func (s *Store) BeginAccount(ctx context.Context, issuer, id, userID, session string, reauth bool) (string, error) {
	if reauth {
		if _, err := s.q.ExternalIdentitySubject(ctx, sqlc.ExternalIdentitySubjectParams{UserID: userID, Provider: id}); errors.Is(err, pgx.ErrNoRows) {
			return "", identity.ErrNotBound
		} else if err != nil {
			return "", err
		}
	}
	to, p, err := s.begin(ctx, issuer, id, func(stateHash []byte, nonce, verifier string) error {
		return s.q.InsertProviderAccountLogin(ctx, sqlc.InsertProviderAccountLoginParams{
			StateHash: stateHash, Provider: id, Nonce: nonce, Verifier: verifier,
			SessionID: pgtype.Text{String: session, Valid: true}, Reauth: reauth,
		})
	})
	if err != nil || !reauth {
		return to, err
	}
	if _, ok := p.(NoReauthPrompt); ok {
		return to, nil
	}
	u, err := url.Parse(to)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("prompt", "login")
	q.Set("max_age", "0")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// finishAccount binds ident to the User of the redirect's Session, or
// reauthenticates the Session with it.
func (s *Store) finishAccount(ctx context.Context, id string, login sqlc.TakeProviderLoginRow, ident Identity) error {
	session := login.SessionID.String
	user, err := s.q.LiveSessionUser(ctx, session)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLogin
	} else if err != nil {
		return err
	}
	if login.Reauth {
		subject, err := s.q.ExternalIdentitySubject(ctx, sqlc.ExternalIdentitySubjectParams{UserID: user, Provider: id})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && subject != ident.Subject {
			return ErrNotYours
		} else if err != nil {
			return err
		}
		// max_age=0: they signed in after the redirect started, give or take
		// the clocks' skew. A Provider that says no auth_time at all passes:
		// OAuth2 has none, and its reauthentication is taken as proof that
		// the External Identity is still signed in upstream (ADR 0013).
		if !ident.AuthTime.IsZero() && ident.AuthTime.Before(login.CreatedAt.Time.Add(-time.Minute)) {
			return ErrNotAfreshAuth
		}
		return s.q.Reauthenticate(ctx, sqlc.ReauthenticateParams{ID: session, UserID: user, Amr: []string{"fed"}})
	}
	token, err := s.sealToken(id, ident)
	if err != nil {
		return err
	}
	err = s.q.BindExternalIdentity(ctx, sqlc.BindExternalIdentityParams{Provider: id, Subject: ident.Subject, UserID: user, Token: token})
	if !isCode(err, "23505") {
		return err
	}
	owner, err := s.q.UserByExternalIdentity(ctx, sqlc.UserByExternalIdentityParams{Provider: id, Subject: ident.Subject})
	switch {
	case errors.Is(err, pgx.ErrNoRows): // the User has another at this Provider
		return ErrBoundAnother
	case err != nil:
		return err
	case owner.UserID == user:
		return nil // bound already
	}
	return ErrTaken
}
