// Package login serves the hosted pages a browser signs in through: the OIDC
// provider with its login page, browser Sessions, and the first-start setup
// page; and the direct auth API Apps sign in through.
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	oidcop "github.com/zibyn/polaris/internal/oidc/provider"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/otp"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/pow"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/twofactor"
)

//go:embed pages.html altcha challenge.openapi.json passkey.js
var pagesFS embed.FS

var pages = template.Must(template.ParseFS(pagesFS, "pages.html"))

const (
	sessionCookie = "__Host-session"

	// Keys in the AuthnSession store, carried into the grant.
	storeAuthTime = "auth_time"
	storeAMR      = "amr"
	// Set instead of a grant while a User past the first factor must still
	// enter a TOTP code, bind a phone number or agree to the terms; with
	// auth_time and amr, and the Session only if the browser already had one.
	storeBindSub = "pending_sub"
	// Set, to the mistakes so far, while the pending login waits for a TOTP
	// code or a 恢复码.
	storeTOTPFailures = "totp_failures"
	// Set while a 待激活 User past the first factor must replace the initial
	// password an admin set (ADR 0016). It comes before 两步验证.
	storeSetPassword = "set_password"
	// The challenge of the login's Passkey options, renewed each time the
	// first step renders; what a replayed assertion fails against.
	storePasskeyChallenge = "passkey_challenge"
	// Set, to the User a Provider just signed in, by the Provider's
	// callback before it sends the browser back to the login.
	storeFederated = "federated_sub"
	// Set with pending_sub or federated_sub: the hash of the binder of the
	// browser the login is for.
	storeBinder = "binder"
	// The Identifier a code was sent to in this login. 重新获取 sends to it
	// again without a new PoW: the value is fixed, and the per-Identifier
	// send limits still apply.
	storeCodeSent = "code_sent"
)

// totpTries is how many wrong TOTP codes or 恢复码 end a login.
const totpTries = 5

// amrMFA marks a login that passed 两步验证 (RFC 8176).
const amrMFA = "mfa"

// amrFed marks a login through a Provider (docs/spec/protocol.md).
const amrFed = "fed"

type Service struct {
	issuer    string
	q         *sqlc.Queries
	ids       *identity.Store
	twoFactor *twofactor.Store
	codes     *otp.Service
	pow       *pow.PoW
	op        *oidcop.Provider
	store     *oidcstore.Store
	providers *provider.Store
	passkeys  *passkey.Store
	origin    *http.CrossOriginProtection
}

// ConsoleClientID is the built-in Application the admin console signs in as.
const ConsoleClientID = "polaris-console"

// AccountClientID is the built-in Application the account center signs in as.
const AccountClientID = "polaris-account"

// New builds the provider and points the redirect URIs of the console and
// the account center at issuer, which only the running instance knows.
func New(ctx context.Context, pool *pgxpool.Pool, keyring *crypt.Keyring, issuer string) (*Service, error) {
	for client, path := range map[string]string{ConsoleClientID: "/console", AccountClientID: "/account"} {
		if err := sqlc.New(pool).SetRedirectURIs(ctx, sqlc.SetRedirectURIsParams{
			ClientID:               client,
			RedirectUris:           []string{issuer + path + "/callback"},
			PostLogoutRedirectUris: []string{issuer + path},
		}); err != nil {
			return nil, err
		}
	}
	work, err := pow.New(ctx, pool)
	if err != nil {
		return nil, err
	}
	passkeys, err := passkey.New(pool, issuer)
	if err != nil {
		return nil, err
	}
	s := &Service{
		issuer:    issuer,
		q:         sqlc.New(pool),
		ids:       identity.New(pool, keyring),
		twoFactor: twofactor.New(pool, keyring),
		codes:     otp.New(pool, channel.NewStore(pool, keyring)),
		pow:       work,
		providers: provider.NewStore(pool, keyring),
		passkeys:  passkeys,
		origin:    http.NewCrossOriginProtection(),
	}
	store := oidcstore.New(pool, keyring)
	s.store = store
	store.Scopes = strings.Join([]string{goidc.ScopeOpenID.ID, goidc.ScopeOfflineAccess.ID, goidc.ScopePhone.ID, goidc.ScopeEmail.ID}, " ")
	op, err := oidcop.New(
		oidcop.Config{
			Issuer:      issuer,
			Manager:     store,
			JWKS:        oidcstore.NewKeys(pool, keyring).JWKS,
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
		oidcop.WithScopes(goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopePhone, goidc.ScopeEmail),
		oidcop.WithClaims(goidc.ClaimPhoneNumber, goidc.ClaimPhoneNumberVerified, goidc.ClaimEmail, goidc.ClaimEmailVerified),
		oidcop.WithNoneAuthn(),
		oidcop.WithSecretBasicAuthn(),
		oidcop.WithSecretPostAuthn(),
		oidcop.WithClientManager(store),
		oidcop.WithClientSecretVerifier(oidcstore.VerifyClientSecret),
		oidcop.WithAuthCodeGrant(
			oidcop.AuthCodeGrantConfig{Manager: store, ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			oidcop.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}),
			oidcop.WithIssuerResponseParameter(),
			oidcop.WithAuthorizationChallengeEndpoint(ChallengePath),
			oidcop.WithAuthPolicies(goidc.NewPolicy("password",
				func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
				s.authenticate)),
		),
		oidcop.WithRefreshTokenGrant(store, oidcop.WithRefreshTokenRotation()),
		// A User whose Roles were all taken away cannot renew forever.
		oidcop.WithGrantHandler(func(ctx context.Context, typ goidc.GrantType, g *goidc.Grant) error {
			if typ != goidc.GrantRefreshToken {
				return nil
			}
			if ok, err := s.mayUse(ctx, g.ClientID, g.Subject); err != nil || ok {
				return err
			}
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, errNoRole)
		}),
		// Only an M2M Application advertises this grant; it mints a token for
		// the Application itself (ADR 0015).
		oidcop.WithClientCredentialsGrant(),
		// Access tokens are JWTs and not stored: revoking one does nothing,
		// and they lapse within their 10 minutes.
		oidcop.WithTokenRevocation(func(context.Context, *goidc.Client) bool { return true }),
		oidcop.WithTokenOptions(func(context.Context, *goidc.Grant, *goidc.Client) goidc.TokenOptions {
			return goidc.NewJWTTokenOptions(goidc.SigAlgRS256, 600)
		}),
		oidcop.WithTokenClaims(s.audience),
		oidcop.WithIDTokenClaims(func(ctx context.Context, g *goidc.Grant) map[string]any {
			claims := s.userClaims(ctx, g)
			claims[goidc.ClaimAuthTime] = g.Store[storeAuthTime]
			claims[goidc.ClaimAMR] = g.Store[storeAMR]
			// Back-Channel Logout names the Session by it.
			if sid, ok := g.Store[oidcstore.SessionKey].(string); ok {
				claims["sid"] = sid
			}
			return claims
		}),
		oidcop.WithUserInfoClaims(s.userClaims),
		oidcop.WithLogout(oidcop.LogoutConfig{
			Manager: store,
			HandleFunc: func(w http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) error {
				page(w, http.StatusOK, "message", "已退出登录")
				return nil
			},
		}, oidcop.WithLogoutPolicies(goidc.NewLogoutPolicy("session",
			func(*http.Request, *goidc.LogoutSession) bool { return true },
			s.logout)), oidcop.WithBackChannelLogout()),
		oidcop.WithErrorRenderer(renderError),
		oidcop.WithErrorHandler(func(_ context.Context, err error) { slog.Info("oidc", "err", err) }),
	)
	if err != nil {
		return nil, err
	}
	s.op = op
	return s, nil
}

// Register adds the OIDC endpoints, the direct auth API and the setup page
// to mux.
func (s *Service) Register(mux *http.ServeMux) {
	s.op.RegisterRoutes(mux, clientCredentialsRules, withDevice, s.cors) // cors outermost: rejected requests get it too
	for path := range corsMethods {
		mux.Handle("OPTIONS "+path, s.cors(http.HandlerFunc(preflight)))
	}
	mux.HandleFunc("GET /altcha/challenge", s.pow.ServeChallenge)
	mux.HandleFunc("GET /altcha/altcha.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFileFS(w, r, pagesFS, "altcha/altcha.js")
	})
	mux.HandleFunc("GET /login/passkey.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFileFS(w, r, pagesFS, "passkey.js")
	})
	mux.HandleFunc("POST "+ChallengePath, s.challenge)
	mux.HandleFunc("GET /v1/auth/terms", s.terms)
	mux.HandleFunc("GET /v1/auth/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, pagesFS, "challenge.openapi.json")
	})
	mux.HandleFunc("GET /login/providers/{id}/callback", s.providerCallback)
	mux.HandleFunc("POST /login/providers/{id}/callback", s.providerCallback)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setup)
	mux.HandleFunc("GET /invite", s.invitePage)
	mux.HandleFunc("POST /invite", s.acceptInvite)
}

// clientCredentialsRules applies ADR 0015 to a client_credentials request:
// its scope is ignored (the token is for the Application's default API and
// grants nothing else), and the secret goes in the Authorization header, not
// the body — an M2M Application authenticates with client_secret_basic only.
// Only an m2m Application may use the grant, so the grant type alone
// identifies such a request, wherever the token endpoint ends up mounted.
func clientCredentialsRules(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.PostFormValue("grant_type") != string(goidc.GrantClientCredentials) {
			next.ServeHTTP(w, r)
			return
		}
		r.PostForm.Del("scope")
		if r.PostFormValue("client_secret") != "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client_credentials requires client_secret_basic"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// audience makes an access token for the Application's default API, with the
// Roles held there (RFC 9068 §2.2.3.1), read as they stand now. A User's
// token carries the User's Roles; an M2M Application's carries its own
// (ADR 0015). It names the Session it was issued in as sid.
// ponytail: two PG reads per token; fold into Client if it shows up.
func (s *Service) audience(ctx context.Context, _ *goidc.Token, g *goidc.Grant) map[string]any {
	claims := map[string]any{}
	if sid, ok := g.Store[oidcstore.SessionKey].(string); ok {
		claims["sid"] = sid
	}
	app, err := s.q.Application(ctx, g.ClientID)
	if err != nil || !app.DefaultApi.Valid {
		return claims
	}
	claims[goidc.ClaimAudience] = app.DefaultApi.String
	var roles, entitlements []string
	if app.Type == "m2m" {
		r, err := s.q.ApplicationTokenRoles(ctx, sqlc.ApplicationTokenRolesParams{ClientID: app.ClientID, Api: app.DefaultApi.String})
		if err != nil {
			slog.Error("token roles", "err", err)
			return claims
		}
		roles, entitlements = r.Roles, r.Entitlements
	} else {
		r, err := s.q.TokenRoles(ctx, sqlc.TokenRolesParams{UserID: g.Subject, Api: app.DefaultApi.String})
		if err != nil {
			slog.Error("token roles", "err", err)
			return claims
		}
		roles, entitlements = r.Roles, r.Entitlements
	}
	if len(roles) > 0 {
		claims["roles"], claims["entitlements"] = roles, entitlements
	}
	return claims
}

// DeleteOldSessions removes Sessions ended or idle for over 30 days; run by
// the hourly cleanup.
func DeleteOldSessions(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteOldSessions(ctx)
}

// authenticate is the hosted login: a live browser Session signs the User in
// silently unless the request demands a fresh login; otherwise the code and
// password forms.
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client) (goidc.Status, error) {
	// A login past its first factor goes on only in its own browser.
	if _, ok := as.Store[storeBindSub]; ok && !sameBinder(r, as.Store[storeBinder]) {
		page(w, http.StatusForbidden, "message", "登录已在其他浏览器中进行,请返回应用重新登录")
		return goidc.StatusPending, nil
	}
	// Only the login form posts to the callback; the authorization request
	// itself may arrive as a cross-site POST.
	if r.Method == http.MethodPost && r.PathValue("callback") != "" {
		return s.submit(w, r, as, c)
	}
	if sub, ok := as.Store[storeFederated].(string); ok && sameBinder(r, as.Store[storeBinder]) {
		return s.login(w, r, as, c, sub, []string{amrFed}, "")
	}
	prompts := strings.Fields(string(as.Prompt))
	none := slices.Contains(prompts, string(goidc.PromptTypeNone))
	if none && len(prompts) > 1 {
		return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeInvalidRequest, "prompt=none cannot be combined with other values")
	}
	sess, err := s.session(w, r)
	if err != nil {
		return goidc.StatusFailure, err
	}
	if sess != nil && !mustLogin(as, sess) {
		if none {
			if needs, err := s.q.NeedsPhone(r.Context(), sess.UserID); err != nil {
				return goidc.StatusFailure, err
			} else if needs {
				return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeInteractionRequired, "a phone number must be bound first")
			}
			if needs, err := s.q.NeedsConsent(r.Context(), sess.UserID); err != nil {
				return goidc.StatusFailure, err
			} else if needs {
				return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeInteractionRequired, "the terms must be agreed to first")
			}
		}
		return s.complete(w, r, as, c, sess.ID, sess.UserID, sess.AuthTime.Time, sess.Amr)
	}
	if none {
		return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeLoginRequired, "login required")
	}
	// The page's links: ?password for the password form, ?identifier to
	// send a code again.
	q := r.URL.Query()
	return s.render(w, r, as, c, loginPage{PasswordForm: q.Has("password"), Identifier: q.Get("identifier"), Recovery: q.Has("recovery")})
}

// mustLogin reports whether the request rules out the existing Session.
// prompt=select_account counts as login: a browser holds one User.
func mustLogin(as *goidc.AuthnSession, sess *sqlc.TouchSessionRow) bool {
	for _, p := range strings.Fields(string(as.Prompt)) {
		if p == string(goidc.PromptTypeLogin) || p == string(goidc.PromptTypeSelectAccount) {
			return true
		}
	}
	if as.MaxAuthnAgeSecs != nil {
		// max_age=0 is prompt=login (Core errata); otherwise re-auth past the age.
		max := time.Duration(*as.MaxAuthnAgeSecs) * time.Second
		if max == 0 || time.Since(sess.AuthTime.Time) > max {
			return true
		}
	}
	return as.IDTokenHintClaims != nil && as.IDTokenHintClaims.Subject != sess.UserID
}

func (s *Service) submit(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client) (goidc.Status, error) {
	ctx := r.Context()
	form := loginPage{Identifier: r.PostFormValue("identifier"), Username: r.PostFormValue("username"), PasswordForm: r.PostFormValue("mode") == "password"}
	if err := s.origin.Check(r); err != nil {
		form.Error = "请从登录页提交"
		return s.render(w, r, as, c, form)
	}
	pending, _ := as.Store[storeBindSub].(string)
	pendingSession, _ := as.Store[oidcstore.SessionKey].(string)
	pendingAuthTime, _ := as.Store[storeAuthTime].(int64)
	terms, err := s.q.Terms(ctx)
	if err != nil {
		return goidc.StatusFailure, err
	}
	// Ticking the box posts the version shown; a stale page agrees to nothing.
	agreed := terms.TermsVersion == "" || r.PostFormValue("agree") == terms.TermsVersion
	// fail shows a mistake on the page, or ends the login on any other error.
	fail := func(err error) (goidc.Status, error) {
		var invalid identity.Invalid
		if !errors.As(err, &invalid) {
			return goidc.StatusFailure, err
		}
		form.Error = invalid.Error()
		return s.render(w, r, as, c, form)
	}

	op := r.PostFormValue("op")
	failures, awaitingTOTP := as.Store[storeTOTPFailures].(int64)
	awaitingPassword := as.Store[storeSetPassword] == true
	switch {
	case awaitingPassword && op != "set-password" && op != "delete-pending":
		// 待激活: nothing else before the User sets their own password —
		// except 注销, which is open to them too.
		return s.render(w, r, as, c, loginPage{})
	case awaitingTOTP && op != "totp":
		return s.render(w, r, as, c, loginPage{}) // nothing else before TOTP
	}
	switch op {
	case "delete-pending":
		// 注销 while 待激活: the User has no token to delete an account
		// with, so they do it from the login they are stuck in (ADR 0016).
		if !awaitingPassword {
			break
		}
		if err := s.deletePending(ctx, pending); err != nil {
			return fail(err)
		}
		as.Store = nil
		page(w, http.StatusOK, "message", "账号已注销")
		return goidc.StatusPending, nil

	case "set-password":
		if !awaitingPassword {
			break
		}
		// The password path of its own (ADR 0016): the account center's
		// would ask for a recent reauthentication, which a User with 两步验证
		// on is refused, and they would never get past this page.
		if err := s.ids.SetPasswordIfPending(ctx, pending, r.PostFormValue("password")); err != nil {
			return fail(err)
		}
		// No consent and no Session: the pending step asked for nothing but
		// the password, so the terms come next as they always would.
		delete(as.Store, storeSetPassword)
		return s.complete(w, r, as, c, "", pending, time.Unix(pendingAuthTime, 0), storedAMR(as.Store[storeAMR]))

	case "totp":
		if !awaitingTOTP {
			break
		}
		form.Recovery = r.PostFormValue("recovery_code") != ""
		amr := storedAMR(as.Store[storeAMR])
		err := s.twoFactor.Check(ctx, clientIP(r), pending, r.PostFormValue("totp"), r.PostFormValue("recovery_code"))
		err = s.ids.LoginFailed(ctx, attempt(r, c.ID), pending, secondFactor(r.PostFormValue("recovery_code")), err)
		switch {
		case err == nil:
			amr = withMFA(amr)
		case errors.Is(err, twofactor.ErrOff): // turned off meanwhile: nothing to enter
		case wrongSecondFactor(err):
			if failures++; failures >= totpTries {
				as.Store = nil
				return s.render(w, r, as, c, loginPage{Error: errTOTPTries.Error()})
			}
			as.Store[storeTOTPFailures] = failures
			return fail(err)
		default:
			return fail(err)
		}
		return s.complete(w, r, as, c, "", pending, time.Unix(pendingAuthTime, 0), amr)

	case "send":
		kind, value, err := identity.ParseIdentifier(form.Identifier)
		if pending == "" && !agreed {
			return fail(errAgree)
		}
		if err != nil && pending == "" && !codeLike.MatchString(strings.TrimSpace(form.Identifier)) {
			// Not shaped like a phone number or email: a username, which
			// signs in by password. Whether it exists is not told.
			if setting, err := s.q.PasswordLogin(ctx); err != nil {
				return goidc.StatusFailure, err
			} else if setting == "off" {
				return fail(errNoCode)
			}
			form.Username, form.Identifier = strings.TrimSpace(form.Identifier), ""
			return s.render(w, r, as, c, form)
		}
		if err == nil && pending != "" && kind != "phone" {
			err = identity.ErrPhone
		}
		if err == nil {
			err = s.pow.Verify(ctx, r.PostFormValue("altcha"))
		}
		if err == nil {
			err = s.codes.Send(ctx, kind, value, clientIP(r))
		}
		if err != nil {
			return fail(err)
		}
		if as.Store == nil {
			as.Store = map[string]any{}
		}
		as.Store[storeCodeSent] = value
		form.Identifier, form.CodeSent = value, true
		return s.render(w, r, as, c, form)

	case "resend":
		// 重新获取 sends again to the Identifier this login already had a
		// code sent to. No second PoW: the value is fixed, and the
		// per-Identifier send limits still apply. Whatever identifier the
		// form posted is ignored, so a resend cannot be turned into a send
		// to someone else.
		sent, _ := as.Store[storeCodeSent].(string)
		kind, value, err := identity.ParseIdentifier(sent)
		if err != nil {
			return s.render(w, r, as, c, loginPage{})
		}
		form.Identifier, form.CodeSent = value, true
		if err := s.codes.Send(ctx, kind, value, clientIP(r)); err != nil {
			return fail(err)
		}
		return s.render(w, r, as, c, form)

	case "verify":
		form.CodeSent = true
		kind, value, err := identity.ParseIdentifier(form.Identifier)
		if err != nil {
			return fail(err)
		}
		if pending == "" && !agreed {
			return fail(errAgree)
		}
		if err := s.ids.FromIP(ctx, clientIP(r), func() error { return s.codes.Check(ctx, value, r.PostFormValue("code")) }); err != nil {
			return fail(s.codeFailed(ctx, attempt(r, c.ID), pending, value, err))
		}
		if pending != "" {
			if kind != "phone" {
				return fail(identity.ErrPhone)
			}
			if err := s.ids.AddIdentifier(ctx, pending, kind, value); err != nil {
				return fail(err)
			}
			return s.complete(w, r, as, c, pendingSession, pending, time.Unix(pendingAuthTime, 0), storedAMR(as.Store[storeAMR]))
		}
		sub, err := s.ids.SignIn(ctx, kind, value)
		if err != nil {
			return fail(err)
		}
		return s.login(w, r, as, c, sub, []string{string(codeAMR(kind))}, terms.TermsVersion)

	case "password":
		if pending != "" {
			break
		}
		if !agreed {
			form.PasswordForm = true // back to the form with the box to tick
			return fail(errAgree)
		}
		var sub string
		a := attempt(r, c.ID)
		if err := s.ids.FromIP(ctx, clientIP(r), func() (err error) {
			sub, err = s.ids.CheckPassword(ctx, a, form.Username, r.PostFormValue("password"))
			return err
		}); err != nil {
			return fail(s.ids.LoginFailed(ctx, a, sub, "password", err))
		}
		return s.login(w, r, as, c, sub, []string{string(goidc.AMRPassword)}, terms.TermsVersion)

	case "passkey":
		if pending != "" {
			break
		}
		challenge, _ := as.Store[storePasskeyChallenge].(string)
		in, err := s.passkeys.SignIn(ctx, challenge, []byte(r.PostFormValue("passkey")))
		if err != nil {
			return fail(err)
		}
		// A Passkey verified the User with the device itself: it is 两步验证
		// already, so the amr claim says mfa and TOTP never comes up. The
		// form is the page's own script that posts it — no box was ticked, so
		// no version: the consent step comes after, as for a Provider.
		return s.login(w, r, as, c, in.Sub, passkey.AMR(in.BackupEligible), "")

	case "provider":
		if pending != "" {
			break
		}
		id := r.PostFormValue("provider")
		to, err := s.providers.Begin(ctx, s.issuer, id, as.ID, binder(w, r))
		if errors.Is(err, provider.ErrNotFound) {
			return fail(errNoProvider)
		} else if err != nil {
			slog.Warn("provider login", "provider", id, "err", err)
			return fail(errProviderDown)
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
		return goidc.StatusPending, nil

	case "consent":
		if pending == "" {
			break
		}
		if !agreed {
			return fail(errAgree)
		}
		if terms.TermsVersion != "" {
			if err := s.q.RecordConsent(ctx, sqlc.RecordConsentParams{UserID: pending, Version: terms.TermsVersion, ClientID: c.ID}); err != nil {
				return goidc.StatusFailure, err
			}
		}
		return s.complete(w, r, as, c, pendingSession, pending, time.Unix(pendingAuthTime, 0), storedAMR(as.Store[storeAMR]))
	}
	return s.render(w, r, as, c, loginPage{})
}

// codeLike is what the page takes for a phone number or email, and runs the
// PoW for; pages.html tests the same.
var codeLike = regexp.MustCompile(`@|^[\d\s+-]+$`)

var (
	errAgree  = identity.Invalid("请先阅读并同意用户协议和隐私政策")
	errNoCode = identity.Invalid("该账号不能用验证码登录")
	// The 5th wrong TOTP code or 恢复码 ends the login.
	errTOTPTries    = identity.Invalid("两步验证错误次数过多,请重新登录")
	errNoProvider   = identity.Invalid("这个外部登录方式已停用")
	errProviderDown = identity.Invalid("暂时无法连接这个外部登录方式,请稍后重试")
)

// needsTOTP reports whether sub, signed in with amr, must still enter a
// TOTP code or a 恢复码: 两步验证 is on and not yet passed.
func (s *Service) needsTOTP(ctx context.Context, sub string, amr []string) (bool, error) {
	if slices.Contains(amr, amrMFA) {
		return false, nil
	}
	return s.twoFactor.On(ctx, sub)
}

// secondFactor is the login.failed method of a TOTP check: a 恢复码 when
// one was given, as twofactor.Check takes it.
func secondFactor(recoveryCode string) string {
	if recoveryCode != "" {
		return "recovery_code"
	}
	return "totp"
}

// codeFailed audits err, from checking a code sent to value, on the User the
// code would sign in: pending, else whoever holds value, if anyone.
func (s *Service) codeFailed(ctx context.Context, a identity.Attempt, pending, value string, err error) error {
	sub := pending
	if sub == "" {
		u, dbErr := s.q.UserByIdentifier(ctx, value)
		if dbErr != nil && !errors.Is(dbErr, pgx.ErrNoRows) {
			return dbErr
		}
		sub = u.UserID
	}
	return s.ids.LoginFailed(ctx, a, sub, "code", err)
}

// wrongSecondFactor reports whether err is a wrong TOTP code or 恢复码: one
// of the tries a pending login has.
func wrongSecondFactor(err error) bool {
	return errors.Is(err, twofactor.ErrCode) || errors.Is(err, twofactor.ErrRecoveryCode)
}

// withMFA is amr after a TOTP code or a 恢复码: the first factor, otp, mfa.
func withMFA(amr []string) []string {
	if !slices.Contains(amr, string(goidc.AMROneTimePassword)) {
		amr = append(amr, string(goidc.AMROneTimePassword))
	}
	return append(amr, amrMFA)
}

// login goes on with a User who just passed the first factor as amr says,
// having agreed to the terms of version (if any).
func (s *Service) login(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client, sub string, amr []string, version string) (goidc.Status, error) {
	if version != "" {
		if err := s.q.RecordConsent(r.Context(), sqlc.RecordConsentParams{UserID: sub, Version: version, ClientID: c.ID}); err != nil {
			return goidc.StatusFailure, err
		}
	}
	return s.complete(w, r, as, c, "", sub, time.Now(), amr)
}

// complete grants sub, unless 待激活, 两步验证, 同意协议 or 绑手机号 still
// stand between them and a Session: those pages come first, in that order.
// Until they are done, the login waits in the AuthnSession store and the
// browser holds no Session; session is empty unless the browser already had
// one (whose login passed 两步验证 already), and the Session starts once
// nothing is left.
func (s *Service) complete(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client, session, sub string, authTime time.Time, amr []string) (goidc.Status, error) {
	// 待激活 comes before 两步验证, 同意协议 and 绑手机号 (ADR 0016), and
	// nextStep owns that order for the direct auth API too. The only evidence
	// so far is that the User knows a password an admin chose, and running the
	// rest of the login on that evidence is what this step refuses.
	//
	// A browser Session already signed in is not re-asked: it cannot exist
	// for a 待激活 User, since they never got past this step.
	what, err := s.nextStep(r.Context(), sub, amr, session != "")
	if err != nil {
		return goidc.StatusFailure, err
	}
	if what != stepDone {
		as.Store = map[string]any{storeBindSub: sub, storeAuthTime: authTime.Unix(), storeAMR: amr, storeBinder: hex.EncodeToString(hash(binder(w, r)))}
		if session != "" {
			as.Store[oidcstore.SessionKey] = session
		}
		if what == stepTOTP {
			as.Store[storeTOTPFailures] = int64(0)
		}
		if what == stepSetPassword {
			as.Store[storeSetPassword] = true
		}
		return s.render(w, r, as, c, loginPage{})
	}
	if session == "" {
		var err error
		if session, err = s.newSession(w, r, c.ID, sub, authTime, amr); err != nil {
			return goidc.StatusFailure, err
		}
	}
	// Turned away only now: the User did sign in, so the browser keeps the
	// Session, and 切换账号 starts over on the login form.
	if ok, err := s.mayUse(r.Context(), c.ID, sub); err != nil {
		return goidc.StatusFailure, err
	} else if !ok {
		if strings.Contains(string(as.Prompt), string(goidc.PromptTypeNone)) {
			return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeAccessDenied, errNoRole)
		}
		as.Store = nil
		page(w, http.StatusForbidden, "denied", loginPage{Client: c.Name, Action: "/authorize/" + as.ID})
		return goidc.StatusPending, nil
	}
	grant(as, session, sub, authTime, amr)
	return goidc.StatusSuccess, nil
}

const errNoRole = "the User holds no Role on the Application's API"

// mayUse reports whether sub may get tokens for the Application clientID.
// One that requires a Role lets in only a User holding one on its default
// API, read as the access token's roles are (docs/spec/rbac.md).
func (s *Service) mayUse(ctx context.Context, clientID, sub string) (bool, error) {
	app, err := s.q.Application(ctx, clientID)
	if err != nil || !app.RequireRole || !app.DefaultApi.Valid {
		return err == nil, err
	}
	r, err := s.q.TokenRoles(ctx, sqlc.TokenRolesParams{UserID: sub, Api: app.DefaultApi.String})
	return len(r.Roles) > 0, err
}

// binderCookie ties a login past its first factor, or through a Provider,
// to the browser that started it.
const binderCookie = "__Host-login"

// binder returns the browser's binder, giving it one if it has none; one
// per browser, so that logins in several tabs each find theirs.
func binder(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(binderCookie); err == nil && c.Value != "" {
		return c.Value
	}
	v := rand.Text()
	http.SetCookie(w, &http.Cookie{Name: binderCookie, Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return v
}

// sameBinder reports whether the browser holds the binder stored hashed
// as want.
func sameBinder(r *http.Request, want any) bool {
	c, err := r.Cookie(binderCookie)
	w, _ := want.(string)
	return err == nil && w != "" && subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash(c.Value))), []byte(w)) == 1
}

// logout is RP-Initiated Logout: it ends the browser Session, and with it
// the refresh tokens issued under it. Unless the Application proves the
// User with an ID token hint, the User confirms first, so that no other
// site can sign them out.
func (s *Service) logout(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return goidc.StatusSuccess, nil //nolint:nilerr // no cookie, nothing to end
	}
	sess, err := s.session(w, r)
	if err != nil {
		return goidc.StatusFailure, err
	} else if sess == nil {
		setSessionCookie(w, "", -1) // a dead Session's cookie
		return goidc.StatusSuccess, nil
	}
	hinted := ls.IDTokenHintClaims != nil && ls.IDTokenHintClaims.Subject == sess.UserID
	confirmed := r.Method == http.MethodPost && r.PathValue("callback") != "" &&
		r.PostFormValue("logout") == "1" && s.origin.Check(r) == nil
	if !hinted && !confirmed {
		page(w, http.StatusOK, "logout", "/logout/"+ls.ID)
		return goidc.StatusPending, nil
	}
	if err := s.q.EndBrowserSession(r.Context(), hash(cookie.Value)); err != nil {
		return goidc.StatusFailure, err
	}
	setSessionCookie(w, "", -1)
	return goidc.StatusSuccess, nil
}

// codeAMR is how a code to an Identifier of kind proves the User (RFC 8176).
func codeAMR(kind string) goidc.AMR {
	if kind == "email" {
		return goidc.AMROneTimePassword
	}
	return goidc.AMRSMS
}

// storedAMR reads amr back from an AuthnSession store, where it was decoded
// from JSON.
func storedAMR(v any) []string {
	switch vs := v.(type) {
	case []string:
		return vs
	case []any:
		out := make([]string, 0, len(vs))
		for _, x := range vs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// withDevice lets the OIDC handlers record the request's device on the
// Session they refresh.
func withDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(deviceContext(r)))
	})
}

func deviceContext(r *http.Request) context.Context {
	return oidcstore.WithDevice(r.Context(), clientIP(r), r.UserAgent())
}

// attempt is where r, a sign-in to clientID, comes from.
func attempt(r *http.Request, clientID string) identity.Attempt {
	return identity.Attempt{ClientID: clientID, IP: clientIP(r), UA: r.UserAgent()}
}

func clientIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return r.RemoteAddr
}

// userClaims are the phone and email claims the grant's scopes ask for.
func (s *Service) userClaims(ctx context.Context, g *goidc.Grant) map[string]any {
	claims := map[string]any{}
	scopes := strings.Fields(g.Scopes)
	ids, err := s.q.UserIdentifiers(ctx, g.Subject)
	if err != nil {
		slog.Error("user claims", "err", err)
		return claims
	}
	for _, id := range ids {
		switch {
		case id.Kind == "phone" && slices.Contains(scopes, goidc.ScopePhone.ID):
			claims[goidc.ClaimPhoneNumber], claims[goidc.ClaimPhoneNumberVerified] = id.Value, true
		case id.Kind == "email" && slices.Contains(scopes, goidc.ScopeEmail.ID):
			claims[goidc.ClaimEmail], claims[goidc.ClaimEmailVerified] = id.Value, true
		}
	}
	return claims
}

// grant completes the AuthnSession for sub, signed in by the browser Session
// session. With no consent page, every requested scope is granted.
func grant(as *goidc.AuthnSession, session, sub string, authTime time.Time, amr []string) {
	as.Subject = sub
	as.GrantedScopes = as.Scopes
	as.Store = map[string]any{oidcstore.SessionKey: session, storeAuthTime: authTime.Unix(), storeAMR: amr}
}

// session returns the browser's live Session, sliding its idle timeout, or
// nil if there is none.
func (s *Service) session(w http.ResponseWriter, r *http.Request) (*sqlc.TouchSessionRow, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil //nolint:nilerr // no cookie, no Session
	}
	ip, ua := oidcstore.Device(deviceContext(r))
	sess, err := s.q.TouchSession(r.Context(), sqlc.TouchSessionParams{IDHash: hash(cookie.Value), Ip: ip, UserAgent: ua})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	setSessionCookie(w, cookie.Value, int(sess.IdleSecs))
	return &sess, nil
}

// newSession signs sub in on this browser, for clientID, and returns the
// Session id. The same User keeps their Session (and the refresh tokens
// under it) with a fresh cookie; another User's Session ends: a browser
// holds one User.
func (s *Service) newSession(w http.ResponseWriter, r *http.Request, clientID, sub string, authTime time.Time, amr []string) (string, error) {
	token := rand.Text()
	ip, ua := oidcstore.Device(deviceContext(r))
	if old, err := r.Cookie(sessionCookie); err == nil {
		sess, err := s.q.RenewSession(r.Context(), sqlc.RenewSessionParams{
			OldHash: hash(old.Value), NewHash: hash(token), UserID: sub,
			AuthTime: pgtype.Timestamptz{Time: authTime, Valid: true}, Amr: amr, Ip: ip, UserAgent: ua,
		})
		if err == nil {
			setSessionCookie(w, token, int(sess.IdleSecs))
			return sess.ID, s.ids.LoginSucceeded(r.Context(), attempt(r, clientID), sub, amr)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if err := s.q.EndBrowserSession(r.Context(), hash(old.Value)); err != nil {
			return "", err
		}
	}
	sess, err := s.q.CreateSession(r.Context(), sqlc.CreateSessionParams{
		IDHash:    hash(token),
		ClientID:  clientID,
		UserID:    sub,
		AuthTime:  pgtype.Timestamptz{Time: authTime, Valid: true},
		Amr:       amr,
		Ip:        ip,
		UserAgent: ua,
	})
	if err != nil {
		return "", err
	}
	setSessionCookie(w, token, int(sess.IdleSecs))
	return sess.ID, s.ids.LoginSucceeded(r.Context(), attempt(r, clientID), sub, amr)
}

// setSessionCookie keeps the cookie as long as the Session's idle timeout;
// maxAge -1 deletes it.
func setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

type loginPage struct {
	Client, Action, Error string
	Terms                 sqlc.TermsRow
	// TOTP: a User past the first factor must enter a TOTP code, or a 恢复码
	// on the Recovery form.
	TOTP, Recovery bool
	// SetPassword: a 待激活 User must replace the admin's initial password
	// before anything else happens (ADR 0016).
	SetPassword bool
	// Consent: a signed-in User must agree to new terms before going on;
	// then Bind: they must bind a phone number.
	Consent, Bind bool
	// CodeKinds names what codes can go to ("手机号", "邮箱" or both); empty
	// when no Channel is enabled. IdentifierLabel adds usernames when
	// PasswordOn: password login is not off.
	CodeKinds, IdentifierLabel string
	PasswordOn                 bool
	// Providers are the buttons of the first step.
	Providers []provider.Button
	// The steps: the first asks for an Identifier, then a code was sent to
	// it (CodeSent) or it was a Username, which takes a password.
	// PasswordForm takes both at once.
	Identifier   string
	CodeSent     bool
	Username     string
	PasswordForm bool
	// Passkey, on the first step: the assertion options embedded in the
	// page, which drive the identifier field's conditional UI, the
	// 使用 Passkey 登录 button and the hidden form their response posts.
	Passkey template.JS
}

func (s *Service) render(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client, p loginPage) (goidc.Status, error) {
	p.Client, p.Action = c.Name, "/authorize/"+as.ID
	ctx := r.Context()
	if pending, ok := as.Store[storeBindSub].(string); ok {
		_, signedIn := as.Store[oidcstore.SessionKey]
		what, err := s.nextStep(ctx, pending, storedAMR(as.Store[storeAMR]), signedIn)
		if err != nil {
			return goidc.StatusFailure, err
		}
		switch what {
		case stepSetPassword:
			p.SetPassword = true
		case stepTOTP:
			p.TOTP = true
		case stepPhone:
			p.Bind = true
		case stepConsent:
			p.Consent = true
		case stepDone:
			// Nothing left (the admin changed the policy meanwhile): the
			// consent page, with no terms to tick, just lets the User go on.
			p.Consent = true
		}
	}
	terms, err := s.q.Terms(ctx)
	if err != nil {
		return goidc.StatusFailure, err
	}
	p.Terms = terms
	setting, err := s.q.PasswordLogin(ctx)
	if err != nil {
		return goidc.StatusFailure, err
	}
	p.PasswordOn = setting != "off"
	kinds, err := s.q.ChannelKinds(ctx)
	if err != nil {
		return goidc.StatusFailure, err
	}
	switch {
	case p.Bind && !slices.Contains(kinds, "phone"):
		p.Error = "需要绑定手机号,但短信通道未配置,请联系管理员"
	case p.Bind || slices.Equal(kinds, []string{"phone"}):
		p.CodeKinds = "手机号"
	case slices.Equal(kinds, []string{"email"}):
		p.CodeKinds = "邮箱"
	case len(kinds) == 2:
		p.CodeKinds = "手机号或邮箱"
	}
	p.IdentifierLabel = p.CodeKinds
	if _, pending := as.Store[storeBindSub]; !pending && !p.TOTP && !p.SetPassword {
		if p.Providers, err = s.providers.Buttons(ctx); err != nil {
			return goidc.StatusFailure, err
		}
	}
	if p.PasswordOn && !p.Bind && !p.SetPassword {
		p.IdentifierLabel = strings.Replace(p.CodeKinds, "或", "、", 1) + "或用户名"
	}
	// The first step carries Passkey assertion options, and a fresh challenge
	// in the store: what makes an assertion for a page already left behind
	// fail. Later steps (code, password, TOTP, consent, bind) carry none.
	// With Passkey login off the page carries none either: no conditional UI,
	// no 「使用 Passkey 登录」 button, and no webauthn autocomplete hint
	// (docs/spec/consoles.md#设置).
	if p.firstStep() {
		on, err := s.passkeys.Enabled(ctx)
		if err != nil {
			return goidc.StatusFailure, err
		}
		if on {
			options, challenge, err := s.passkeys.LoginOptions(ctx)
			if err != nil {
				return goidc.StatusFailure, err
			}
			if as.Store == nil {
				as.Store = map[string]any{}
			}
			as.Store[storePasskeyChallenge] = challenge
			p.Passkey = template.JS(options)
		}
	}
	page(w, http.StatusOK, "login", p)
	return goidc.StatusPending, nil
}

// firstStep reports whether the page shows a form that starts a login: the
// identifier one, or the username and password one an instance without
// Channels offers. A Passkey can start a login from either.
func (p loginPage) firstStep() bool {
	return !p.TOTP && !p.Consent && !p.Bind && !p.SetPassword && !p.CodeSent &&
		(p.Username == "" || p.PasswordForm)
}

// renderError shows an authorization error that cannot go back to the
// Application (unknown client, bad redirect_uri).
func renderError(w http.ResponseWriter, _ *http.Request, err error) error {
	msg := "请求无效"
	var oidcErr goidc.Error
	if errors.As(err, &oidcErr) {
		msg = oidcErr.Description
	}
	page(w, http.StatusBadRequest, "message", msg)
	return nil
}

func page(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render", "page", name, "err", err)
	}
}
