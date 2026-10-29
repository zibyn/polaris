// Package oidcstore keeps the OIDC protocol layer's state in PostgreSQL:
// Applications as clients, grants and sessions, and the signing keys.
package oidcstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// Store implements the go-oidc storage interfaces.
type Store struct {
	q       *sqlc.Queries
	keyring *crypt.Keyring
	// Scopes every Application may request, space-separated.
	Scopes string
	// GrantTTL keeps a grant around for the tokens issued from it when no
	// longer-lived secret (auth code, refresh token) does; at least the
	// access token lifetime.
	GrantTTL time.Duration
	// JTITTL keeps a used jti until its JWT can no longer be valid: go-oidc's
	// longest JWT lifetime plus clock skew. ConsumeJTI never sees the JWT's exp.
	JTITTL time.Duration
}

var (
	_ goidc.ClientManager       = (*Store)(nil)
	_ goidc.GrantManager        = (*Store)(nil)
	_ goidc.AuthManager         = (*Store)(nil)
	_ goidc.RefreshTokenManager = (*Store)(nil)
	_ goidc.LogoutManager       = (*Store)(nil)
)

// SessionKey is the grant Store key holding the id of the Session the grant
// was issued in; such a grant works only while that Session lives.
const SessionKey = "session"

// SessionDefaults are the 闲置时长 and 寿命上限, in seconds, of a browser or
// App Session whose Application sets none (docs/spec/protocol.md#session).
func SessionDefaults(browser bool) (idleSecs, maxSecs int32) {
	if browser {
		return 30 * 86400, 90 * 86400
	}
	return 90 * 86400, 180 * 86400
}

// CreateSession signs sub in for clientID: a browser Session under the
// cookie hash idHash, or an App Session if idHash is nil. Its device comes
// from ctx (WithDevice). pgx.ErrNoRows: the User is disabled.
func (s *Store) CreateSession(ctx context.Context, idHash []byte, clientID, sub string, authTime time.Time, amr []string) (sqlc.CreateSessionRow, error) {
	ip, ua := Device(ctx)
	idle, maxLife := SessionDefaults(idHash != nil)
	return s.q.CreateSession(ctx, sqlc.CreateSessionParams{
		IDHash: idHash, ClientID: clientID, UserID: sub, AuthTime: pgtype.Timestamptz{Time: authTime, Valid: true},
		Amr: amr, Ip: ip, UserAgent: ua, DefaultIdleSecs: idle, DefaultMaxSecs: maxLife,
	})
}

// GraceWindow is how long the refresh token a rotation spent last still
// rotates its grant again instead of counting as reuse (ADR 0019).
const GraceWindow = 60 * time.Second

// graceKey marks, in the grant Store, a grant loaded by a spent refresh token
// in its grace window; never saved.
const graceKey = "polaris.grace"

// errReused answers a refresh token that was already rotated away.
var errReused = goidc.NewError(goidc.ErrorCodeInvalidGrant, "refresh token reused")

func New(pool *pgxpool.Pool, keyring *crypt.Keyring) *Store {
	// 600s is go-oidc's default JWTLifetimeSecs, which login does not override.
	return &Store{q: sqlc.New(pool), keyring: keyring, GrantTTL: time.Hour, JTITTL: 600*time.Second + time.Minute}
}

// errJTIReplayed answers a jti seen before; go-oidc maps it to the error code
// of the DPoP proof or client assertion it came in.
var errJTIReplayed = errors.New("jti already used")

// ConsumeJTI is the goidc.ConsumeJTIFunc: a jti is good once until it
// expires. The primary key makes one of concurrent uses win, across replicas.
func (s *Store) ConsumeJTI(ctx context.Context, jti string) error {
	n, err := s.q.ConsumeJTI(ctx, sqlc.ConsumeJTIParams{
		Jti:       jti,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(s.JTITTL), Valid: true},
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errJTIReplayed
	}
	return nil
}

// DeleteExpired removes expired grants, sessions and retired signing keys;
// run by the hourly cleanup.
func DeleteExpired(ctx context.Context, pool *pgxpool.Pool) error {
	q := sqlc.New(pool)
	if err := q.DeleteExpiredOIDC(ctx); err != nil {
		return err
	}
	return q.DeleteRetiredSigningKeys(ctx, keyRetention)
}

// Client resolves an Application. Confidential Applications authenticate with
// their secret (basic or post), or with an assertion signed by a registered
// key once switched to private_key_jwt (ADR 0023); public ones with PKCE
// only. An M2M Application authenticates the same ways, but only for the
// client_credentials grant: it has no login, so no authorization code
// (ADR 0015).
func (s *Store) Client(ctx context.Context, id string) (*goidc.Client, error) {
	app, err := s.q.Application(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	c := &goidc.Client{
		ID: app.ClientID,
		ClientMeta: goidc.ClientMeta{
			Name:                   app.Name,
			TokenAuthnMethod:       goidc.AuthnMethodNone,
			RedirectURIs:           app.RedirectUris,
			PostLogoutRedirectURIs: app.PostLogoutRedirectUris,
			GrantTypes:             []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:          []goidc.ResponseType{goidc.ResponseTypeCode},
			ScopeIDs:               s.Scopes,
		},
	}
	if app.RefreshTokens {
		c.GrantTypes = append(c.GrantTypes, goidc.GrantRefreshToken)
	}
	switch app.Type {
	case "m2m":
		c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
		c.Secret = hex.EncodeToString(app.SecretHash)
		c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
	case "confidential":
		c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
		c.Secret = hex.EncodeToString(app.SecretHash)
	}
	if app.Type != "public" && app.TokenAuthMethod == string(goidc.AuthnMethodPrivateKeyJWT) {
		c.TokenAuthnMethod, c.Secret = goidc.AuthnMethodPrivateKeyJWT, ""
		c.JWKS = &goidc.JSONWebKeySet{}
		if err := json.Unmarshal(app.Jwks, c.JWKS); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Application is what CreateApplication needs; a Secret makes it confidential.
type Application struct {
	ClientID               string
	Name                   string
	Type                   string // "" derives it from Secret
	Secret                 string
	DefaultAPI             string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
}

func CreateApplication(ctx context.Context, pool *pgxpool.Pool, app Application) error {
	params := sqlc.CreateApplicationParams{
		ClientID: app.ClientID,
		Name:     app.Name,
		Type:     "public",
		// Non-nil: pgx writes a nil slice as NULL.
		RedirectUris:           append([]string{}, app.RedirectURIs...),
		PostLogoutRedirectUris: append([]string{}, app.PostLogoutRedirectURIs...),
		DefaultApi:             pgtype.Text{String: app.DefaultAPI, Valid: app.DefaultAPI != ""},
		BackchannelLogoutUri:   pgtype.Text{String: app.BackchannelLogoutURI, Valid: app.BackchannelLogoutURI != ""},
	}
	if app.Secret != "" {
		params.Type = "confidential"
		params.SecretHash = hash(app.Secret)
	}
	if app.Type != "" {
		params.Type = app.Type
	}
	return sqlc.New(pool).CreateApplication(ctx, params)
}

// SecretHash is how a client secret is stored.
func SecretHash(secret string) []byte { return hash(secret) }

// VerifyClientSecret checks a presented secret against the stored hash (the
// hex Client.Secret); plug it in with provider.WithClientSecretVerifier.
func VerifyClientSecret(_ context.Context, stored, presented string) error {
	want, err := hex.DecodeString(stored)
	if err != nil || subtle.ConstantTimeCompare(want, hash(presented)) != 1 {
		return errors.New("invalid client secret")
	}
	return nil
}

func (s *Store) SaveGrant(ctx context.Context, g *goidc.Grant) error {
	_, grace := g.Store[graceKey]
	delete(g.Store, graceKey)
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	sealed, err := s.keyring.Seal(data, grantAAD(g.ID))
	if err != nil {
		return err
	}
	if g.PreviousRefreshToken != "" {
		ip, ua := Device(ctx)
		n, err := s.q.RotateRefreshToken(ctx, sqlc.RotateRefreshTokenParams{
			ID: g.ID, OldHash: hash(g.PreviousRefreshToken), NewHash: hash(g.RefreshToken),
			ExpiresAt: s.grantExpiry(g), Sealed: sealed, Ip: ip, UserAgent: ua,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			// Spent already: a retry in the grace window, or a concurrent
			// request rotated it first. Either way rotate from the current token.
			n, err = s.q.GraceRotateRefreshToken(ctx, sqlc.GraceRotateRefreshTokenParams{
				OldHash: hash(g.PreviousRefreshToken), GraceSecs: int32(GraceWindow.Seconds()),
				NewHash: hash(g.RefreshToken), ExpiresAt: s.grantExpiry(g), Sealed: sealed,
				Ip: ip, UserAgent: ua,
			})
			if err != nil {
				return err
			}
		}
		if n == 0 {
			if err := s.q.EndReusedRefreshToken(ctx, hash(g.PreviousRefreshToken)); err != nil {
				return err
			}
			return errReused
		}
		return nil
	}
	if g.RevokedAt != 0 && grace {
		// Revoking a spent token ends the Session, grace window or not.
		return s.q.EndReusedRefreshToken(ctx, hash(g.RefreshToken))
	}
	session, _ := g.Store[SessionKey].(string)
	return s.q.SaveGrant(ctx, sqlc.SaveGrantParams{
		ID:               g.ID,
		ClientID:         g.ClientID,
		AuthCodeHash:     hash(g.AuthCode),
		RefreshTokenHash: hash(g.RefreshToken),
		ExpiresAt:        s.grantExpiry(g),
		SessionID:        pgtype.Text{String: session, Valid: session != ""},
		Sealed:           sealed,
		Revoked:          g.RevokedAt != 0,
	})
}

func (s *Store) grantExpiry(g *goidc.Grant) pgtype.Timestamptz {
	if g.RefreshToken != "" && g.RefreshTokenExpiresAt == 0 {
		return pgtype.Timestamptz{} // lives as long as its refresh token
	}
	exp := max(time.Now().Add(s.GrantTTL).Unix(), int64(g.AuthCodeExpiresAt), int64(g.RefreshTokenExpiresAt))
	return pgtype.Timestamptz{Time: time.Unix(exp, 0), Valid: true}
}

func (s *Store) Grant(ctx context.Context, id string) (*goidc.Grant, error) {
	return s.openGrant(s.q.Grant(ctx, id))
}

func (s *Store) GrantByAuthCode(ctx context.Context, code string) (*goidc.Grant, error) {
	return s.openGrant(s.q.GrantByAuthCodeHash(ctx, hash(code)))
}

// GrantByRefreshToken also catches reuse: a token that a rotation replaced
// ends the Session it was issued in, wherever it shows up (refresh or
// revocation, from any client), since it has leaked. The token rotated away
// last gets a grace window: its grant comes back as if the token were still
// current, and SaveGrant rotates it from the actual current one (ADR 0019).
func (s *Store) GrantByRefreshToken(ctx context.Context, token string) (*goidc.Grant, error) {
	g, err := s.openGrant(s.q.GrantByRefreshTokenHash(ctx, hash(token)))
	if !errors.Is(err, goidc.ErrNotFound) {
		return g, err
	}
	id, err := s.q.GraceRefreshToken(ctx, sqlc.GraceRefreshTokenParams{Hash: hash(token), GraceSecs: int32(GraceWindow.Seconds())})
	if err == nil {
		g, err := s.Grant(ctx, id)
		if err == nil {
			g.RefreshToken = token
			if g.Store == nil {
				g.Store = map[string]any{}
			}
			g.Store[graceKey] = true
			return g, nil
		}
		if !errors.Is(err, goidc.ErrNotFound) {
			return nil, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := s.q.EndReusedRefreshToken(ctx, hash(token)); err != nil {
		return nil, err
	}
	return nil, goidc.ErrNotFound
}

func (s *Store) openGrant(row sqlc.OidcGrant, err error) (*goidc.Grant, error) {
	if err != nil {
		return nil, notFound(err)
	}
	data, err := s.keyring.Open(row.Sealed, grantAAD(row.ID))
	if err != nil {
		return nil, err
	}
	var g goidc.Grant
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	ints(g.Store)
	return &g, nil
}

// SaveSession stores go-oidc's in-flight authorization state; not a
// glossary Session (a User's login on a device).
func (s *Store) SaveSession(ctx context.Context, as *goidc.AuthnSession) error {
	data, err := json.Marshal(as)
	if err != nil {
		return err
	}
	return s.q.SaveAuthnSession(ctx, sqlc.SaveAuthnSessionParams{ID: as.ID, ExpiresAt: unix(as.ExpiresAt), Data: data})
}

func (s *Store) Session(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	data, err := s.q.AuthnSession(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	var as goidc.AuthnSession
	if err := json.Unmarshal(data, &as); err != nil {
		return nil, err
	}
	ints(as.Store)
	return &as, nil
}

func (s *Store) SaveLogoutSession(ctx context.Context, ls *goidc.LogoutSession) error {
	data, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	return s.q.SaveLogoutSession(ctx, sqlc.SaveLogoutSessionParams{ID: ls.ID, ExpiresAt: unix(ls.ExpiresAt), Data: data})
}

func (s *Store) LogoutSession(ctx context.Context, id string) (*goidc.LogoutSession, error) {
	data, err := s.q.LogoutSession(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}
	var ls goidc.LogoutSession
	return &ls, json.Unmarshal(data, &ls)
}

// ints turns integral numbers in a decoded Store back into int64. JSON has one
// number type, and claims kept there (auth_time) are re-signed later: go-jose
// would write a float64 as 1.791302791e+09, which is not a NumericDate.
func ints(v any) any {
	switch v := v.(type) {
	case float64:
		if v == math.Trunc(v) && math.Abs(v) <= 1<<53 {
			return int64(v)
		}
	case map[string]any:
		for k, e := range v {
			v[k] = ints(e)
		}
	case []any:
		for i, e := range v {
			v[i] = ints(e)
		}
	}
	return v
}

// hash indexes a bearer secret; nil (SQL NULL) when there is none.
func hash(secret string) []byte {
	if secret == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func grantAAD(id string) []byte { return []byte("oidc_grant:" + id) }

func unix(secs int) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Unix(int64(secs), 0), Valid: true}
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return goidc.ErrNotFound
	}
	return err
}
