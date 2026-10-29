// Package account serves the Account API, where a signed-in User manages
// their own account from the account center, and the direct auth API's
// account deletion for Apps.
package account

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/otp"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/twofactor"
)

// Prefix is where the Account API lives; its OpenAPI document is at
// Prefix + "/openapi.json".
const Prefix = "/v1/account"

// recent is how long ago a User must have authenticated for a sensitive
// action (docs/spec/identity.md#换绑与解绑).
const recent = 10 * time.Minute

// DeletePath is the direct auth API's account deletion, for Apps.
const DeletePath = "/v1/auth/delete"

type Service struct {
	issuer    string
	pool      *pgxpool.Pool
	q         *sqlc.Queries
	keys      *oidcstore.Keys
	ids       *identity.Store
	codes     *otp.Service
	twoFactor *twofactor.Store
	providers *provider.Store
	passkeys  *passkey.Store
}

func New(pool *pgxpool.Pool, keyring *crypt.Keyring, issuer string) (*Service, error) {
	passkeys, err := passkey.New(pool, issuer)
	if err != nil {
		return nil, err
	}
	return &Service{
		issuer: issuer, pool: pool, q: sqlc.New(pool), keys: oidcstore.NewKeys(pool, keyring),
		ids: identity.New(pool, keyring), codes: otp.New(pool, channel.NewStore(pool, keyring)),
		twoFactor: twofactor.New(pool, keyring), providers: provider.NewStore(pool, keyring),
		passkeys: passkeys,
	}, nil
}

type callerKey struct{}

// caller is the User a request comes from, the Session it comes from and
// when they last authenticated in it.
type caller struct {
	sub, session, ip, ua string
	authTime             time.Time
	// 待激活, read with the Session; see AccountSession.
	pending bool
}

func callerOf(ctx context.Context) caller { return ctx.Value(callerKey{}).(caller) }

// Register adds the Account API, its OpenAPI document, the direct auth
// API's account deletion and the account center's /.well-known/ discovery
// files to mux.
func (s *Service) Register(mux *http.ServeMux) {
	s.passkeys.RegisterWellKnown(mux)
	s.registerChangePassword(mux)
	cfg := huma.DefaultConfig("Polaris Account API", "1")
	cfg.DocsPath = ""
	cfg.SchemasPath = ""
	cfg.CreateHooks = nil
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {Type: "http", Scheme: "bearer", BearerFormat: "JWT",
			Description: "The account center's access token, whose aud is " + identity.AccountAPI},
	}
	cfg.Security = []map[string][]string{{"bearer": {}}}
	mux.HandleFunc("POST "+DeletePath, s.directDelete)
	api := humago.NewWithPrefix(mux, Prefix, cfg)
	api.UseMiddleware(s.authorize(api))

	op(api, http.MethodGet, "me", "/me", "The signed-in User", s.me)
	op(api, http.MethodPost, "send-reauth-code", "/reauth/code", "Send a code to one of the User's Identifiers, to reauthenticate with", s.sendReauthCode)
	op(api, http.MethodPost, "reauth", "/reauth", "Reauthenticate this Session with a code, the password or a Passkey", s.reauth)
	op(api, http.MethodPost, "begin-passkey-reauth", "/reauth/passkey", "Begin reauthenticating with one of the User's Passkeys: assertion options for the browser or native App", s.beginPasskeyReauth)
	// Sensitive actions answer 403 until the User has reauthenticated in the last 10 minutes.
	op(api, http.MethodPost, "send-identifier-code", "/identifiers/{kind}/code", "Send a code to a phone number or email to bind", s.sendIdentifierCode, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodPut, "put-identifier", "/identifiers/{kind}", "Bind a phone number or email with its code, replacing the User's", s.putIdentifier, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodDelete, "remove-identifier", "/identifiers/{kind}", "Unbind the User's phone number or email", s.removeIdentifier, http.StatusForbidden)
	op(api, http.MethodPut, "put-password", "/password", "Set or change the User's password", s.putPassword, http.StatusForbidden)
	op(api, http.MethodDelete, "delete-account", "/me", "Delete the User's account and all their data, at once", s.deleteAccount, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodGet, "list-sessions", "/sessions", "The User's Sessions", s.listSessions)
	op(api, http.MethodDelete, "end-session", "/sessions/{id}", "Sign one of the User's Sessions out", s.endSession, http.StatusNotFound)
	op(api, http.MethodGet, "export", "/export", "The User's data, as a JSON download", s.export, http.StatusForbidden)
	op(api, http.MethodDelete, "remove-password", "/password", "Delete the User's password", s.removePassword, http.StatusForbidden)
	op(api, http.MethodPost, "begin-totp", "/2fa/totp", "Begin turning 两步验证 on: a new TOTP to add to an authenticator, replacing one not yet confirmed", s.beginTOTP, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodPost, "confirm-totp", "/2fa/totp/confirm", "Turn 两步验证 on with a code from the new TOTP; the recovery codes are shown this once", s.confirmTOTP, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodDelete, "disable-2fa", "/2fa", "Turn 两步验证 off, deleting the TOTP and recovery codes; 409 for an admin while 管理员必须启用两步验证或 Passkey is on and no Passkey is left", s.disableTwoFactor, http.StatusForbidden, http.StatusConflict)
	// A Provider redirect comes back to the account center with ?bound=<id>,
	// ?reauthenticated=<id> or ?error=<what to show the User>.
	op(api, http.MethodPost, "bind-provider", "/providers/{id}/bind", "Where to send the browser to bind an External Identity of the enabled Provider", s.bindProvider, http.StatusForbidden, http.StatusNotFound)
	op(api, http.MethodPost, "reauth-with-provider", "/providers/{id}/reauth", "Where to send the browser to reauthenticate at the bound Provider; 422 with 两步验证 on", s.reauthWithProvider, http.StatusNotFound)
	op(api, http.MethodDelete, "unbind-provider", "/providers/{id}", "Unbind the User's External Identity of the Provider", s.unbindProvider, http.StatusForbidden)
	op(api, http.MethodPost, "regenerate-recovery-codes", "/2fa/recovery-codes", "Replace the recovery codes with a new set", s.regenerateRecoveryCodes, http.StatusForbidden)
	op(api, http.MethodGet, "list-logins", "/logins", "The User's sign-ins, failed sign-ins and password lockouts of the last 30 days", s.listLogins)
	op(api, http.MethodGet, "list-passkeys", "/passkeys", "The User's Passkeys", s.listPasskeys)
	op(api, http.MethodPost, "begin-passkey", "/passkeys/options", "Begin adding a Passkey: creation options for the browser or native App", s.beginPasskey, http.StatusForbidden)
	op(api, http.MethodPost, "add-passkey", "/passkeys", "Finish adding a Passkey with its registration response", s.addPasskey, http.StatusForbidden, http.StatusConflict)
	op(api, http.MethodPatch, "rename-passkey", "/passkeys/{id}", "Rename one of the User's Passkeys; no reauthentication needed", s.renamePasskey, http.StatusNotFound)
	op(api, http.MethodDelete, "remove-passkey", "/passkeys/{id}", "Delete one of the User's Passkeys; 409 for the last one while 管理员必须启用两步验证或 Passkey is on, no TOTP is left and the User holds a Role", s.removePasskey, http.StatusForbidden, http.StatusNotFound, http.StatusConflict)
}

// registerChangePassword serves /.well-known/change-password, where a
// password manager sends a User whose saved password it found weak or
// leaked. It lands them in the account center's 安全 section. With password
// login off there is nothing to change, so it is not served
// (docs/spec/authentication.md「密码管理器适配」).
func (s *Service) registerChangePassword(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		setting, err := s.q.PasswordLogin(r.Context())
		if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if setting == "off" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, s.issuer+"/account#passkeys", http.StatusFound)
	})
}

// op registers an operation; errs are its errors beyond the usual.
func op[I, O any](api huma.API, method, id, path, summary string, h func(context.Context, *I) (*O, error), errs ...int) {
	errs = append(errs, http.StatusUnauthorized)
	if method != http.MethodGet {
		errs = append(errs, http.StatusUnprocessableEntity)
	}
	huma.Register(api, huma.Operation{OperationID: id, Method: method, Path: path, Summary: summary, Errors: errs}, h)
}

// authorize lets in the account center's access tokens while the Session
// they were issued in lives: signing out a device locks it out at once.
func (s *Service) authorize(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c, err := s.caller(ctx.Context(), identity.AccountAPI, ctx.Header("Authorization"))
		if errors.Is(err, oidcstore.ErrToken) {
			ctx.SetHeader("WWW-Authenticate", `Bearer error="invalid_token"`)
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "access token missing or invalid, or its Session ended")
			return
		} else if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "internal error")
			return
		}
		// 待激活: no token is ever issued to such a User — the sign-in stops
		// at setting a password — so this is normally unreachable. Checked
		// anyway: "no token exists" is the whole of the protection, so a
		// token that did turn up must not open the account center.
		if c.pending {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "账号待激活,请先设置密码")
			return
		}
		r, _ := humago.Unwrap(ctx)
		c.ip, c.ua = clientIP(r), r.UserAgent()
		next(huma.WithValue(ctx, callerKey{}, c))
	}
}

// caller checks an access token for audience ("" for any) and the Session
// it was issued in.
func (s *Service) caller(ctx context.Context, audience, header string) (caller, error) {
	tok, err := s.keys.Verify(ctx, s.issuer, audience, header)
	if err != nil {
		return caller{}, err
	}
	sess, err := s.q.AccountSession(ctx, sqlc.AccountSessionParams{ID: tok.SessionID, UserID: tok.Subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return caller{}, oidcstore.ErrToken
	} else if err != nil {
		return caller{}, err
	}
	return caller{sub: tok.Subject, session: tok.SessionID, authTime: sess.AuthTime.Time, pending: sess.Pending}, nil
}

type Identifier struct {
	Kind  string `json:"kind" enum:"phone,email,username"`
	Value string `json:"value"`
}

type meOutput struct {
	Body struct {
		Sub             string       `json:"sub"`
		CreatedAt       time.Time    `json:"createdAt"`
		Identifiers     []Identifier `json:"identifiers" nullable:"false"`
		HasPassword     bool         `json:"hasPassword"`
		PasswordAllowed bool         `json:"passwordAllowed" doc:"The password login setting lets this User sign in with, and set, a password"`
		RecentAuthUntil time.Time    `json:"recentAuthUntil" doc:"Until when sensitive actions need no reauthentication"`
		TwoFactor       TwoFactor    `json:"twoFactor"`
		PasskeyLogin    bool         `json:"passkeyLogin" doc:"The instance offers Passkey login: the account center shows the Passkey section and reauthentication way only then"`
		// External Identities and the Providers to bind.
		ExternalIdentities []ExternalIdentity `json:"externalIdentities" nullable:"false"`
		Providers          []Provider         `json:"providers" nullable:"false" doc:"The enabled Providers, to bind or reauthenticate at"`
	}
}

type ExternalIdentity struct {
	Provider string    `json:"provider" doc:"Provider ID"`
	Name     string    `json:"name" doc:"The Provider's name"`
	Enabled  bool      `json:"enabled" doc:"Whether the Provider is enabled: it signs in and reauthenticates only then"`
	BoundAt  time.Time `json:"boundAt"`
}

type Provider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TwoFactor is the User's 两步验证, never its secrets.
type TwoFactor struct {
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabledAt,omitempty"`
	RecoveryCodesLeft int64      `json:"recoveryCodesLeft"`
}

func twoFactorOf(u sqlc.AccountUserRow) TwoFactor {
	t := TwoFactor{Enabled: u.TwoFactorSince.Valid, RecoveryCodesLeft: u.RecoveryCodesLeft}
	if t.Enabled {
		t.EnabledAt = &u.TwoFactorSince.Time
	}
	return t
}

func (s *Service) me(ctx context.Context, _ *struct{}) (*meOutput, error) {
	c := callerOf(ctx)
	u, err := s.q.AccountUser(ctx, c.sub)
	if err != nil {
		return nil, err
	}
	out := &meOutput{}
	b := &out.Body
	b.Sub, b.CreatedAt, b.HasPassword, b.PasswordAllowed = c.sub, u.CreatedAt.Time, u.HasPassword, u.PasswordAllowed
	b.RecentAuthUntil, b.TwoFactor, b.PasskeyLogin = c.authTime.Add(recent), twoFactorOf(u), u.PasskeyLogin
	if b.ExternalIdentities, err = s.externalIdentities(ctx, c.sub); err != nil {
		return nil, err
	}
	buttons, err := s.providers.Buttons(ctx)
	if err != nil {
		return nil, err
	}
	b.Providers = []Provider{}
	for _, p := range buttons {
		b.Providers = append(b.Providers, Provider{ID: p.ID, Name: p.Name})
	}
	return out, json.Unmarshal(u.Identifiers, &b.Identifiers)
}

func (s *Service) externalIdentities(ctx context.Context, sub string) ([]ExternalIdentity, error) {
	list, err := s.providers.ExternalIdentities(ctx, sub)
	out := []ExternalIdentity{}
	for _, x := range list {
		out = append(out, ExternalIdentity{Provider: x.Provider, Name: x.Name, Enabled: x.Enabled, BoundAt: x.CreatedAt})
	}
	return out, err
}

type providerPath struct {
	ID string `path:"id"`
}

type redirectOutput struct {
	Body struct {
		URL string `json:"url" doc:"Where to send the browser"`
	}
}

func (s *Service) bindProvider(ctx context.Context, in *providerPath) (*redirectOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	return s.redirect(ctx, in.ID, false)
}

func (s *Service) reauthWithProvider(ctx context.Context, in *providerPath) (*redirectOutput, error) {
	if on, err := s.twoFactor.On(ctx, callerOf(ctx).sub); err != nil || on {
		return nil, fail(cmp.Or(err, error(errTwoFactorOnly)))
	}
	return s.redirect(ctx, in.ID, true)
}

func (s *Service) redirect(ctx context.Context, id string, reauth bool) (*redirectOutput, error) {
	c := callerOf(ctx)
	out := &redirectOutput{}
	var err error
	out.Body.URL, err = s.providers.BeginAccount(ctx, s.issuer, id, c.sub, c.session, reauth)
	if errors.Is(err, provider.ErrNotFound) {
		return nil, huma.Error404NotFound("没有启用这个外部登录")
	}
	return out, fail(err)
}

func (s *Service) unbindProvider(ctx context.Context, in *providerPath) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	sub := callerOf(ctx).sub
	return nil, fail(s.providers.Unbind(ctx, sub, in.ID, sub))
}

// fresh refuses a sensitive action unless the User authenticated in this
// Session within the last 10 minutes.
func fresh(ctx context.Context) error {
	if time.Since(callerOf(ctx).authTime) > recent {
		return huma.Error403Forbidden("请先重新验证身份")
	}
	return nil
}

// fail shows the User a mistake of theirs; other errors stay internal.
func fail(err error) error {
	var invalid identity.Invalid
	if errors.As(err, &invalid) {
		return huma.Error422UnprocessableEntity(invalid.Error())
	}
	return err
}

// identifier is the User's Identifier of kind.
func (s *Service) identifier(ctx context.Context, kind string) (string, error) {
	ids, err := s.q.UserIdentifiers(ctx, callerOf(ctx).sub)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		if id.Kind == kind {
			return id.Value, nil
		}
	}
	return "", identity.ErrNotBound
}

type kindBody struct {
	Body struct {
		Kind string `json:"kind" enum:"phone,email"`
	}
}

// errTwoFactorOnly refuses a code or the password to a User with 两步验证 on.
const errTwoFactorOnly identity.Invalid = "已开启两步验证,请输入验证器中的验证码或恢复码"

func (s *Service) sendReauthCode(ctx context.Context, in *kindBody) (*struct{}, error) {
	if on, err := s.twoFactor.On(ctx, callerOf(ctx).sub); err != nil || on {
		return nil, fail(cmp.Or(err, error(errTwoFactorOnly)))
	}
	value, err := s.identifier(ctx, in.Body.Kind)
	if err == nil {
		err = s.codes.Send(ctx, in.Body.Kind, value, callerOf(ctx).ip)
	}
	return nil, fail(err)
}

type reauthInput struct {
	Body struct {
		Kind         string `json:"kind,omitempty" enum:"phone,email" doc:"Where the code went"`
		Code         string `json:"code,omitempty"`
		Password     string `json:"password,omitempty" doc:"Instead of a code"`
		TOTP         string `json:"totp,omitempty" doc:"A code from the User's TOTP; with 两步验证 on, this or a recovery code is the only way"`
		RecoveryCode string `json:"recoveryCode,omitempty" doc:"One of the User's recovery codes, instead of a TOTP code; used up"`
		Passkey      string `json:"passkey,omitempty" doc:"The assertion response from POST /reauth/passkey; a Passkey has passed 两步验证 already"`
	}
}

// passkeyOptionsOutput is what beginning a Passkey ceremony answers: the
// creation or assertion options for the browser or native App.
type passkeyOptionsOutput struct {
	Body struct {
		Options json.RawMessage `json:"options" doc:"Options as sent to the browser: the PublicKeyCredentialCreationOptionsJSON or PublicKeyCredentialRequestOptionsJSON under publicKey, which goes to navigator.credentials.create or get, or the system credential API"`
	}
}

// beginPasskeyReauth starts reauthenticating with a Passkey; the options name
// only the User's own Passkeys.
func (s *Service) beginPasskeyReauth(ctx context.Context, _ *struct{}) (*passkeyOptionsOutput, error) {
	c := callerOf(ctx)
	js, err := s.passkeys.ReauthOptions(ctx, c.sub, c.session)
	if err != nil {
		return nil, fail(err)
	}
	out := &passkeyOptionsOutput{}
	out.Body.Options = js
	return out, nil
}

// reauth makes a fresh authentication of this Session, counted toward the
// same lockouts as logging in; a Passkey is one attempt per challenge, as at
// login. With 两步验证 on, only a TOTP, recovery code or Passkey does; a
// Passkey is 两步验证 by itself.
func (s *Service) reauth(ctx context.Context, in *reauthInput) (*struct{}, error) {
	c := callerOf(ctx)
	if in.Body.Passkey != "" {
		return nil, passkeyErr(s.reauthPasskey(ctx, in.Body.Passkey))
	}
	on, err := s.twoFactor.On(ctx, c.sub)
	if err != nil {
		return nil, err
	}
	if on {
		return nil, fail(s.reauthTwoFactor(ctx, in))
	}
	var amr string
	err = s.ids.FromIP(ctx, c.ip, func() error {
		if in.Body.Password != "" {
			amr = "pwd"
			ids, err := s.q.UserIdentifiers(ctx, c.sub)
			if err != nil || len(ids) == 0 {
				return cmp.Or(err, error(identity.ErrBadCredentials))
			}
			sub, err := s.ids.CheckPassword(ctx, identity.Attempt{IP: c.ip, UA: c.ua}, ids[0].Value, in.Body.Password)
			if err == nil && sub != c.sub {
				err = identity.ErrBadCredentials
			}
			return err
		}
		amr = "sms"
		if in.Body.Kind == "email" {
			amr = "otp"
		}
		value, err := s.identifier(ctx, in.Body.Kind)
		if err != nil {
			return err
		}
		return s.codes.Check(ctx, value, in.Body.Code)
	})
	if err != nil {
		return nil, fail(err)
	}
	return nil, s.q.Reauthenticate(ctx, sqlc.ReauthenticateParams{ID: c.session, UserID: c.sub, Amr: []string{amr}})
}

// reauthTwoFactor reauthenticates with a TOTP or recovery code; a wrong one
// counts toward the IP lockout like a wrong code.
func (s *Service) reauthTwoFactor(ctx context.Context, in *reauthInput) error {
	c := callerOf(ctx)
	if in.Body.TOTP == "" && in.Body.RecoveryCode == "" {
		return errTwoFactorOnly
	}
	if err := s.twoFactor.Check(ctx, c.ip, c.sub, in.Body.TOTP, in.Body.RecoveryCode); err != nil {
		return err
	}
	return s.q.Reauthenticate(ctx, sqlc.ReauthenticateParams{ID: c.session, UserID: c.sub, Amr: []string{"otp", "mfa"}})
}

// reauthPasskey reauthenticates with one of the User's Passkeys, writing the
// amr a Passkey sign-in writes.
func (s *Service) reauthPasskey(ctx context.Context, response string) error {
	c := callerOf(ctx)
	in, err := s.passkeys.Reauth(ctx, c.sub, c.session, []byte(response))
	if err != nil {
		return err
	}
	return s.q.Reauthenticate(ctx, sqlc.ReauthenticateParams{ID: c.session, UserID: c.sub, Amr: passkey.AMR(in.BackupEligible)})
}

type kindPath struct {
	Kind string `path:"kind" enum:"phone,email"`
}

func (s *Service) removeIdentifier(ctx context.Context, in *kindPath) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	return nil, fail(s.ids.RemoveIdentifier(ctx, callerOf(ctx).sub, in.Kind))
}

type identifierInput struct {
	Kind string `path:"kind" enum:"phone,email"`
	Body struct {
		Value string `json:"value" doc:"+86 phone number or email; normalised"`
		Code  string `json:"code,omitempty" doc:"The code sent to it; only to bind it"`
	}
}

// parse normalises the value to bind.
func (in *identifierInput) parse() (string, error) {
	kind, value, err := identity.ParseIdentifier(in.Body.Value)
	if err == nil && kind != in.Kind {
		err = identity.ErrIdentifier
	}
	return value, err
}

func (s *Service) sendIdentifierCode(ctx context.Context, in *identifierInput) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	value, err := in.parse()
	if err != nil {
		return nil, fail(err)
	}
	// No code for what is not the User's to take.
	if u, err := s.q.UserByIdentifier(ctx, value); err == nil && u.UserID != callerOf(ctx).sub {
		return nil, huma.Error409Conflict(identity.ErrIdentifierTaken.Error())
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return nil, fail(s.codes.Send(ctx, in.Kind, value, callerOf(ctx).ip))
}

func (s *Service) putIdentifier(ctx context.Context, in *identifierInput) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	c := callerOf(ctx)
	value, err := in.parse()
	if err == nil {
		err = s.ids.FromIP(ctx, c.ip, func() error { return s.codes.Check(ctx, value, in.Body.Code) })
	}
	if err == nil {
		err = s.ids.ReplaceIdentifier(ctx, c.sub, in.Kind, value, c.sub)
	}
	if errors.Is(err, identity.ErrIdentifierTaken) {
		return nil, huma.Error409Conflict(err.Error())
	}
	return nil, fail(err)
}

type passwordInput struct {
	Body struct {
		Password string `json:"password" doc:"At least 8 characters"`
	}
}

func (s *Service) putPassword(ctx context.Context, in *passwordInput) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	sub := callerOf(ctx).sub
	u, err := s.q.AccountUser(ctx, sub)
	if err != nil {
		return nil, err
	}
	if !u.PasswordAllowed {
		return nil, huma.Error422UnprocessableEntity("密码登录未开启,不能设置密码")
	}
	return nil, fail(s.ids.SetPassword(ctx, sub, in.Body.Password))
}

func (s *Service) removePassword(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	return nil, fail(s.ids.RemovePassword(ctx, callerOf(ctx).sub))
}

type totpOutput struct {
	Body struct {
		URI    string `json:"uri" doc:"otpauth:// URI, for the QR code"`
		Secret string `json:"secret" doc:"Base32, to paste into a password manager"`
	}
}

func (s *Service) beginTOTP(ctx context.Context, _ *struct{}) (*totpOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	sub := callerOf(ctx).sub
	ids, err := s.q.UserIdentifiers(ctx, sub)
	if err != nil {
		return nil, err
	}
	out := &totpOutput{}
	if out.Body.Secret, err = s.twoFactor.Begin(ctx, sub); err != nil {
		return nil, twoFactorErr(err)
	}
	u, err := url.Parse(s.issuer)
	if err != nil {
		return nil, err
	}
	out.Body.URI = twofactor.URI(u.Hostname(), masked(sub, ids), out.Body.Secret)
	return out, nil
}

// masked is the User's primary Identifier as an authenticator's entry shows
// it: 138****8000, a***@example.com.
func masked(sub string, ids []sqlc.UserIdentifiersRow) string {
	for _, kind := range []string{"phone", "email", "username"} {
		for _, id := range ids {
			if id.Kind != kind {
				continue
			}
			switch v := id.Value; kind {
			case "phone":
				v = strings.TrimPrefix(v, "+86")
				return v[:3] + "****" + v[len(v)-4:]
			case "email":
				name, domain, _ := strings.Cut(v, "@")
				return name[:1] + "***@" + domain
			default:
				return v
			}
		}
	}
	return sub
}

type recoveryCodesOutput struct {
	Body struct {
		RecoveryCodes []string `json:"recoveryCodes" doc:"10 codes, each usable once instead of a TOTP code; shown only now"`
	}
}

type confirmTOTPInput struct {
	Body struct {
		Code string `json:"code" doc:"A code the authenticator shows"`
	}
}

func (s *Service) confirmTOTP(ctx context.Context, in *confirmTOTPInput) (*recoveryCodesOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	out := &recoveryCodesOutput{}
	var err error
	out.Body.RecoveryCodes, err = s.twoFactor.Confirm(ctx, callerOf(ctx).sub, in.Body.Code)
	return out, twoFactorErr(err)
}

// disableTwoFactor turns 两步验证 off; the User's other Sessions stay.
func (s *Service) disableTwoFactor(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	sub := callerOf(ctx).sub
	// The switch would be pointless if admins could turn 两步验证 off; a
	// Passkey left satisfies it just as well.
	if must, err := s.q.MustKeepTwoFactor(ctx, sub); err != nil {
		return nil, err
	} else if must {
		return nil, huma.Error409Conflict("管理员必须启用两步验证或 Passkey,你持有管理员角色,不能关闭")
	}
	return nil, twoFactorErr(s.twoFactor.Disable(ctx, sub, "mfa.disabled", sub))
}

func (s *Service) regenerateRecoveryCodes(ctx context.Context, _ *struct{}) (*recoveryCodesOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	out := &recoveryCodesOutput{}
	var err error
	out.Body.RecoveryCodes, err = s.twoFactor.RegenerateRecoveryCodes(ctx, callerOf(ctx).sub)
	return out, twoFactorErr(err)
}

// twoFactorErr is 409 for 两步验证 already on.
func twoFactorErr(err error) error {
	if errors.Is(err, twofactor.ErrOn) {
		return huma.Error409Conflict(err.Error())
	}
	return fail(err)
}

// deleteAccount deletes the User for good (docs/spec/identity.md#注销): their
// Sessions and refresh tokens go with them, and their Identifiers are free
// at once. Their Providers' unlink hooks run after (Apple revokes).
func (s *Service) deleteAccount(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	err := s.providers.DeleteUser(ctx, callerOf(ctx).sub, s.ids.Delete)
	if errors.Is(err, identity.ErrLastOwner) {
		return nil, huma.Error409Conflict(err.Error())
	}
	return nil, err
}

// directDelete is account deletion for Apps: the App's access token, issued
// in a Session the User signed in to in the last 10 minutes, deletes them.
// Errors follow RFC 6750, and RFC 9470 for a sign-in too old.
func (s *Service) directDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.caller(ctx, "", r.Header.Get("Authorization"))
	if err == nil && time.Since(c.authTime) > recent {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="sign in again first", max_age="600"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err == nil {
		err = s.providers.DeleteUser(ctx, c.sub, s.ids.Delete)
	}
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, oidcstore.ErrToken):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Is(err, identity.ErrLastOwner):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": err.Error()})
	default:
		slog.Error("delete account", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func clientIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// passkeyErr is fail plus 404 for a Passkey that is not the User's.
func passkeyErr(err error) error {
	if errors.Is(err, passkey.ErrGone) {
		return huma.Error404NotFound("没有这把 Passkey")
	}
	return fail(err)
}

type passkeysOutput struct {
	Body struct {
		Passkeys []passkey.Passkey `json:"passkeys" nullable:"false" doc:"Oldest first"`
	}
}

func (s *Service) listPasskeys(ctx context.Context, _ *struct{}) (*passkeysOutput, error) {
	list, err := s.passkeys.List(ctx, callerOf(ctx).sub)
	if err != nil {
		return nil, err
	}
	out := &passkeysOutput{}
	out.Body.Passkeys = list
	return out, nil
}

// beginPasskey starts adding a Passkey; the options exclude the User's
// existing credentials so an authenticator offers no second copy of one.
func (s *Service) beginPasskey(ctx context.Context, _ *struct{}) (*passkeyOptionsOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	c := callerOf(ctx)
	ids, err := s.q.UserIdentifiers(ctx, c.sub)
	if err != nil {
		return nil, err
	}
	js, err := s.passkeys.Begin(ctx, c.sub, masked(c.sub, ids), c.session)
	if err != nil {
		return nil, fail(err)
	}
	out := &passkeyOptionsOutput{}
	out.Body.Options = js
	return out, nil
}

type addPasskeyInput struct {
	Body passkey.RegistrationResponse
}

type passkeyOutput struct {
	Body passkey.Passkey
}

// addPasskey finishes what beginPasskey began, with the registration
// response the browser or App got back.
func (s *Service) addPasskey(ctx context.Context, in *addPasskeyInput) (*passkeyOutput, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	c := callerOf(ctx)
	response, err := json.Marshal(in.Body)
	if err != nil {
		return nil, err
	}
	added, err := s.passkeys.Finish(ctx, c.sub, c.session, response)
	if errors.Is(err, passkey.ErrDuplicate) {
		return nil, huma.Error409Conflict(err.Error())
	}
	if err != nil {
		return nil, passkeyErr(err)
	}
	out := &passkeyOutput{}
	out.Body = added
	return out, nil
}

type renamePasskeyInput struct {
	ID   string `path:"id"`
	Body struct {
		Name string `json:"name" doc:"How the User knows this Passkey, such as 工作电脑"`
	}
}

func (s *Service) renamePasskey(ctx context.Context, in *renamePasskeyInput) (*struct{}, error) {
	c := callerOf(ctx)
	return nil, passkeyErr(s.passkeys.Rename(ctx, c.sub, in.ID, in.Body.Name, c.sub))
}

func (s *Service) removePasskey(ctx context.Context, in *providerPath) (*struct{}, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	c := callerOf(ctx)
	// Deleting the last Passkey would lock a Role-holding User out of the
	// Management API while the switch is on and no TOTP is left.
	if must, err := s.q.MustKeepPasskey(ctx, sqlc.MustKeepPasskeyParams{Sub: c.sub, ID: in.ID}); err != nil {
		return nil, err
	} else if must {
		return nil, huma.Error409Conflict("管理员必须启用两步验证或 Passkey,你持有管理员角色,不能删除最后一把 Passkey")
	}
	return nil, passkeyErr(s.passkeys.Remove(ctx, c.sub, in.ID, c.sub))
}
