package authutil

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidc/conformance/ui"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
	"github.com/zibyn/polaris/internal/oidcstore"
)

func Policy() goidc.AuthnPolicy {
	tmpl := template.Must(template.ParseFS(ui.FS, "template.html"))
	authenticator := authenticator{tmpl: tmpl}
	return goidc.NewPolicy(
		"main",
		func(r *http.Request, as *goidc.AuthnSession, c *goidc.Client) bool {
			// The flow starts at the login step.
			as.Store = map[string]any{
				paramStepID: stepIDLoadUser,
			}

			if c.LogoURI != "" {
				as.Store[paramLogoURI] = c.LogoURI
			}
			if c.PolicyURI != "" {
				as.Store[paramPolicyURI] = c.PolicyURI
			}
			if c.TermsOfServiceURI != "" {
				as.Store[paramTermsOfServiceURI] = c.TermsOfServiceURI
			}

			return true
		},
		authenticator.authenticate,
	)
}

const (
	paramStepID         string = "step_id"
	stepIDLoadUser      string = "step_load_user"
	stepIDLogin         string = "step_login"
	stepIDCreateSession string = "step_create_session"
	stepIDConsent       string = "step_consent"
	stepIDFinishFlow    string = "step_finish_flow"

	paramAuthTime          string = "auth_time"
	paramUserSessionToken  string = "user_session_token"
	paramLogoURI           string = "logo_uri"
	paramPolicyURI         string = "policy_uri"
	paramTermsOfServiceURI string = "tos_uri"
	paramIDTokenClaims     string = "id_token_claims"
	paramUserInfoClaims    string = "userinfo_claims"

	usernameFormParam string = "username"
	passwordFormParam string = "password"
	loginFormParam    string = "login"
	consentFormParam  string = "consent"

	cookieUserSessionID string = "goidc_username"

	correctPassword string = "pass"
)

var userSessionStore = map[string]userSession{}

var (
	sessions *oidcstore.Store
	q        *sqlc.Queries
)

// UseSessions gives the harness Polaris's Session storage and queries. The
// harness still keeps its login session in memory (a test fixture over
// goidc's policy API); each one is mirrored into a Polaris Session, so that
// ending it queues the Applications' logout tokens, which webhook.Sender
// delivers (ADR 0022). Users are bare rows: the harness has no Identifiers.
func UseSessions(store *oidcstore.Store, pool *pgxpool.Pool) {
	sessions, q = store, sqlc.New(pool)
}

type authnPage struct {
	Subject           string
	BaseURL           string
	CallbackID        string
	LogoURI           string
	PolicyURI         string
	TermsOfServiceURI string
	Error             string
	Session           map[string]any
}

type userSession struct {
	// Token is the browser cookie's value; ID is the Polaris Session row's
	// id, the sid of the tokens issued in it.
	Token    string
	ID       string
	Subject  string
	AuthTime int
}

type authenticator struct {
	tmpl *template.Template
}

func (a authenticator) authenticate(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {

	if as.Store[paramStepID] == stepIDLoadUser {
		if status, err := a.loadUser(r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.Store[paramStepID] = stepIDLogin
	}

	if as.Store[paramStepID] == stepIDLogin {
		if status, err := a.login(w, r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.Store[paramStepID] = stepIDCreateSession
	}

	if as.Store[paramStepID] == stepIDCreateSession {
		if status, err := a.createUserSession(w, r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.Store[paramStepID] = stepIDConsent
	}

	if as.Store[paramStepID] == stepIDConsent {
		if status, err := a.grantConsent(w, r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.Store[paramStepID] = stepIDFinishFlow
	}

	if as.Store[paramStepID] == stepIDFinishFlow {
		return a.finishFlow(as)
	}

	return goidc.StatusFailure, errors.New("access denied")
}

func (a authenticator) loadUser(r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) { //nolint:unparam
	// Never do this in production, it's just an example.
	if as.IDTokenHintClaims != nil {
		as.Subject = as.IDTokenHintClaims.Subject
		as.Store[paramAuthTime] = as.IDTokenHintClaims.AuthTime
	}

	cookie, err := r.Cookie(cookieUserSessionID)
	if err != nil {
		return goidc.StatusSuccess, nil //nolint:nilerr
	}

	session, ok := userSessionStore[cookie.Value]
	if !ok {
		return goidc.StatusSuccess, nil
	}

	as.Subject = session.Subject
	as.Store[paramAuthTime] = session.AuthTime
	as.Store[paramUserSessionToken] = session.Token
	return goidc.StatusSuccess, nil
}

func (a authenticator) login(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {

	// If the user is unknown and the client requested no prompt for credentials,
	// return a login-required error.
	if as.Subject == "" && as.Prompt == goidc.PromptTypeNone {
		return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeLoginRequired, "user not logged in, cannot use prompt none")
	}

	// Determine if authentication is required.
	// Authentication is required if the user's identity is unknown or if the
	// client explicitly requested a login.
	mustAuthenticate := as.Subject == "" || as.Prompt == goidc.PromptTypeLogin
	// Additionally, check if the client specified a max age for the session.
	// If the max age is exceeded or 'auth_time' is unavailable, force re-authentication.
	if as.MaxAuthnAgeSecs != nil {
		maxAgeSecs := *as.MaxAuthnAgeSecs
		authTime, ok := storedAuthTime(as)
		if !ok || timeutil.TimestampNow() > authTime+maxAgeSecs {
			mustAuthenticate = true
		}
	}
	if !mustAuthenticate {
		return goidc.StatusSuccess, nil
	}

	login := r.PostFormValue(loginFormParam)
	if login == "" {
		return a.renderPage(w, "login", as)
	}

	if login != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	username := r.PostFormValue(usernameFormParam)
	password := r.PostFormValue(passwordFormParam)
	if password != correctPassword {
		return a.renderError(w, "login", as, fmt.Sprintf("invalid password, try '%s'", correctPassword))
	}

	as.Subject = username
	as.Store[paramAuthTime] = timeutil.TimestampNow()
	return goidc.StatusSuccess, nil
}

func (a authenticator) createUserSession(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {
	token, _ := as.Store[paramUserSessionToken].(string)
	session, ok := userSessionStore[token]
	if ok && session.Subject != as.Subject {
		// Another User on this browser: that Session ends, and its
		// Applications get logout tokens.
		if err := q.EndBrowserSession(r.Context(), hash(session.Token)); err != nil {
			return goidc.StatusFailure, err
		}
		delete(userSessionStore, session.Token)
		ok = false
	}
	if !ok {
		var err error
		session, err = newSession(r.Context(), as.ClientID, as.Subject, must(storedAuthTime(as)))
		if err != nil {
			return goidc.StatusFailure, err
		}
	}
	userSessionStore[session.Token] = session
	as.Store[paramUserSessionToken] = session.Token
	as.Store[oidcstore.SessionKey] = session.ID
	setSessionCookie(w, session.Token, 0)
	return goidc.StatusSuccess, nil
}

// newSession signs sub in on this browser with a Polaris Session row. The
// harness logs in any username; the User row it needs is made on first login.
func newSession(ctx context.Context, clientID, sub string, authTime int) (userSession, error) {
	if err := q.CreateUser(ctx, sub); err != nil {
		// The same username signs in for many test modules.
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.ConstraintName != "users_pkey" {
			return userSession{}, err
		}
	}
	token := rand.Text()
	row, err := sessions.CreateSession(ctx, hash(token), clientID, sub,
		time.Unix(int64(authTime), 0), []string{string(goidc.AMRPassword)}, "password")
	if err != nil {
		return userSession{}, err
	}
	return userSession{Token: token, ID: row.ID, Subject: sub, AuthTime: authTime}, nil
}

func hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieUserSessionID,
		Value:    token,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func (a authenticator) grantConsent(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {
	consented := r.PostFormValue(consentFormParam)
	if consented == "" {
		return a.renderPage(w, "consent", as)
	}

	if consented != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	return goidc.StatusSuccess, nil
}

func (a authenticator) finishFlow(as *goidc.AuthnSession) (goidc.Status, error) {
	as.GrantedScopes = as.Scopes
	as.GrantedResources = as.Resources
	as.GrantedAuthDetails = as.AuthDetails

	idTokenClaims := map[string]any{
		goidc.ClaimAuthTime: must(storedAuthTime(as)),
		goidc.ClaimACR:      string(goidc.ACRMaceIncommonIAPSilver),
	}
	// Back-Channel Logout names the Session by it.
	if sid, ok := as.Store[oidcstore.SessionKey].(string); ok {
		idTokenClaims["sid"] = sid
	}
	userInfoClaims := map[string]any{}

	// Add claims based on the claims parameter.
	if as.Claims != nil {

		// acr claim.
		if acrClaim, ok := as.Claims.IDToken[goidc.ClaimACR]; ok {
			idTokenClaims[goidc.ClaimACR] = acrClaim.Value
		}
		if acrClaim, ok := as.Claims.UserInfo[goidc.ClaimACR]; ok {
			userInfoClaims[goidc.ClaimACR] = acrClaim.Value
		}

		// name claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimName]; ok {
			idTokenClaims[goidc.ClaimName] = "John Michael Doe"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimName]; ok {
			userInfoClaims[goidc.ClaimName] = "John Michael Doe"
		}

		// email claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmail]; ok {
			idTokenClaims[goidc.ClaimEmail] = "random@email.com"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmail]; ok {
			userInfoClaims[goidc.ClaimEmail] = "random@email.com"
		}

		// email_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmailVerified]; ok {
			idTokenClaims[goidc.ClaimEmailVerified] = true
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmailVerified]; ok {
			userInfoClaims[goidc.ClaimEmailVerified] = true
		}

		// phone_number claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumber]; ok {
			idTokenClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumber]; ok {
			userInfoClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		}

		// phone_number_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumberVerified]; ok {
			idTokenClaims[goidc.ClaimPhoneNumberVerified] = true
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumberVerified]; ok {
			userInfoClaims[goidc.ClaimPhoneNumberVerified] = true
		}

		// address claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimAddress]; ok {
			idTokenClaims[goidc.ClaimAddress] = addressClaim()
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimAddress]; ok {
			userInfoClaims[goidc.ClaimAddress] = addressClaim()
		}
	}

	// Add claims based on scope.
	// Scope-based claims go to id_token for implicit grant, userinfo otherwise.
	scopeClaims := userInfoClaims
	if as.ResponseType == goidc.ResponseTypeIDToken {
		scopeClaims = idTokenClaims
	}
	if strings.Contains(as.Scopes, goidc.ScopeEmail.ID) {
		scopeClaims[goidc.ClaimEmail] = "random@email.com"
		scopeClaims[goidc.ClaimEmailVerified] = true
	}
	if strings.Contains(as.Scopes, goidc.ScopePhone.ID) {
		scopeClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		scopeClaims[goidc.ClaimPhoneNumberVerified] = true
	}
	if strings.Contains(as.Scopes, goidc.ScopeAddress.ID) {
		scopeClaims[goidc.ClaimAddress] = addressClaim()
	}
	if strings.Contains(as.Scopes, goidc.ScopeProfile.ID) {
		scopeClaims[goidc.ClaimWebsite] = "https://example.com"
		scopeClaims[goidc.ClaimZoneInfo] = "America/Sao_Paulo"
		scopeClaims[goidc.ClaimBirthdate] = "1990-01-01"
		scopeClaims[goidc.ClaimGender] = "male"
		scopeClaims[goidc.ClaimProfile] = "https://example.com/johndoe"
		scopeClaims[goidc.ClaimPreferredUsername] = "johndoe"
		scopeClaims[goidc.ClaimGivenName] = "John"
		scopeClaims[goidc.ClaimMiddleName] = "Michael"
		scopeClaims[goidc.ClaimLocale] = "en-US"
		scopeClaims[goidc.ClaimPicture] = "https://example.com/johndoe/profile.jpg"
		scopeClaims[goidc.ClaimUpdatedAt] = timeutil.TimestampNow()
		scopeClaims[goidc.ClaimName] = "John Michael Doe"
		scopeClaims[goidc.ClaimNickname] = "Johnny"
		scopeClaims[goidc.ClaimFamilyName] = "Doe"
	}

	as.Store[paramIDTokenClaims] = idTokenClaims
	as.Store[paramUserInfoClaims] = userInfoClaims

	return goidc.StatusSuccess, nil
}

func addressClaim() map[string]any {
	return map[string]any{
		"street_address": "123 Main St, Suite 500",
		"locality":       "Springfield",
		"region":         "IL",
		"postal_code":    "62701",
		"country":        "USA",
	}
}

func (a authenticator) renderPage(w http.ResponseWriter, tmplName string, as *goidc.AuthnSession) (goidc.Status, error) {

	params := authnPage{
		Subject:    as.Subject,
		BaseURL:    Issuer,
		CallbackID: as.ID,
		Session:    mapify(as),
	}

	if logoURI, ok := as.Store[paramLogoURI]; ok {
		params.LogoURI = logoURI.(string)
	}

	if policyURI, ok := as.Store[paramPolicyURI]; ok {
		params.PolicyURI = policyURI.(string)
	}

	if termsOfService, ok := as.Store[paramTermsOfServiceURI]; ok {
		params.TermsOfServiceURI = termsOfService.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.tmpl.ExecuteTemplate(w, tmplName, params)
	return goidc.StatusPending, nil
}

func (a authenticator) renderError(w http.ResponseWriter, tmplName string, as *goidc.AuthnSession, err string) (goidc.Status, error) {

	params := authnPage{
		Subject:    as.Subject,
		BaseURL:    Issuer,
		CallbackID: as.ID,
		Session:    mapify(as),
		Error:      err,
	}

	if logoURI, ok := as.Store[paramLogoURI]; ok {
		params.LogoURI = logoURI.(string)
	}

	if policyURI, ok := as.Store[paramPolicyURI]; ok {
		params.PolicyURI = policyURI.(string)
	}

	if termsOfService, ok := as.Store[paramTermsOfServiceURI]; ok {
		params.TermsOfServiceURI = termsOfService.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.tmpl.ExecuteTemplate(w, tmplName, params)
	return goidc.StatusPending, nil
}

func mapify(as any) map[string]any {
	data, err := json.Marshal(as)
	if err != nil {
		panic(err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		panic(err)
	}
	return m
}

// storedAuthTime reads auth_time back from the session store: an int until
// the session is persisted, an int64 after (internal/oidcstore).
func storedAuthTime(as *goidc.AuthnSession) (int, bool) {
	switch v := as.Store[paramAuthTime].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

func must(authTime int, ok bool) int {
	if !ok {
		panic("auth_time missing from the session store")
	}
	return authTime
}
