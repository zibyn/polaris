package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/joseutil"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
)

type Context struct {
	Response http.ResponseWriter
	Request  *http.Request
	context  context.Context
	*Configuration
}

func NewHTTPContext(w http.ResponseWriter, r *http.Request, config *Configuration) Context {
	return Context{
		Configuration: config,
		Response:      w,
		Request:       r,
	}
}

func NewContext(ctx context.Context, config *Configuration) Context {
	return Context{
		Configuration: config,
		context:       ctx,
	}
}

func Handler(config *Configuration, exec func(ctx Context)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exec(NewHTTPContext(w, r, config))
	}
}

func (ctx Context) Scope(s string) (goidc.Scope, bool) {
	for _, scope := range ctx.Scopes {
		if scope.Matches(s) {
			return scope, true
		}
	}
	return goidc.Scope{}, false
}

func (ctx Context) AuthSaveSession(as *goidc.AuthnSession) error {
	return ctx.AuthManager.SaveSession(ctx, as)
}

func (ctx Context) AuthSession(id string) (*goidc.AuthnSession, error) {
	return ctx.AuthManager.Session(ctx, id)
}

func (ctx Context) GrantByAuthCode(code string) (*goidc.Grant, error) {
	return ctx.AuthManager.GrantByAuthCode(ctx, code)
}

func (ctx Context) TokenAuthnSigAlgs() []goidc.SignatureAlgorithm {
	var sigAlgs []goidc.SignatureAlgorithm

	if slices.Contains(ctx.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) {
		sigAlgs = append(sigAlgs, ctx.AuthnMethodPrivateKeyJWTSigAlgs...)
	}

	if slices.Contains(ctx.AuthnMethods, goidc.AuthnMethodSecretJWT) {
		sigAlgs = append(sigAlgs, ctx.AuthnMethodSecretJWTSigAlgs...)
	}

	return sigAlgs
}

func (ctx Context) TokenIntrospectionIsClientAllowed(c *goidc.Client, info goidc.TokenInfo) bool {
	return ctx.TokenIntrospectionIsClientAllowedFunc(ctx, c, info)
}

func (ctx Context) TokenRevocationIsClientAllowed(c *goidc.Client) bool {
	return ctx.TokenRevocationIsClientAllowedFunc(ctx, c)
}

func (ctx Context) ConsumeJTI(jti string) error {
	return ctx.ConsumeJTIFunc(ctx, jti)
}

func (ctx Context) RenderError(err error) error {
	if ctx.RenderErrorFunc == nil {
		// No need to notify error here, since this error will end up being
		// passed to WriteError which already calls it.
		return err
	}

	ctx.HandleError(err)
	return ctx.RenderErrorFunc(ctx.Response, ctx.Request, err)
}

func (ctx Context) HandleError(err error) {
	ctx.HandleErrorFunc(ctx, err)
}

func (ctx Context) VerifyClientSecret(stored, presented string) error {
	return ctx.VerifyClientSecretFunc(ctx, stored, presented)
}

func (ctx Context) Issuer() string {
	return ctx.Host
}

func (ctx Context) TokenURL() string {
	return ctx.BaseURL() + ctx.TokenEndpoint
}

func (ctx Context) RequestURL() string {
	return ctx.Issuer() + ctx.Request.RequestURI
}

func (ctx Context) Policy(policies []goidc.AuthnPolicy, id string) goidc.AuthnPolicy {
	for _, policy := range policies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.AuthnPolicy{
		Authenticate: func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client) (goidc.Status, error) {
			return goidc.StatusFailure, goidc.ErrNotFound
		},
	}
}

func (ctx Context) LogoutPolicy(id string) goidc.LogoutPolicy {
	for _, policy := range ctx.LogoutPolicies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.LogoutPolicy{
		Logout: func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
			return goidc.StatusFailure, goidc.ErrNotFound
		},
	}
}

func (ctx Context) RARValidateDetail(detail goidc.AuthDetail) error {
	return ctx.RARValidateDetailFunc(ctx, detail)
}

func (ctx Context) RARCompareAuthDetails(requested, granted []goidc.AuthDetail) error {
	return ctx.RARCompareDetailsFunc(ctx, requested, granted)
}

func (ctx Context) HandleDefaultPostLogout(session *goidc.LogoutSession) error {
	return ctx.HandleDefaultPostLogoutFunc(ctx.Response, ctx.Request, session)
}

func (ctx Context) LogoutSessionID() string {
	return ctx.LogoutSessionIDFunc(ctx)
}

func (ctx Context) AuthnSessionID() string {
	return ctx.AuthSessionIDFunc(ctx)
}

func (ctx Context) GrantID() string {
	return ctx.GrantIDFunc(ctx)
}

func (ctx Context) JWTID() string {
	return ctx.JWTIDFunc(ctx)
}

func (ctx Context) AuthCode() string {
	return ctx.AuthCodeFunc(ctx)
}

func (ctx Context) OpaqueTokenValue(grant *goidc.Grant) string {
	return ctx.OpaqueTokenFunc(ctx, grant)
}

func (ctx Context) SaveGrant(grant *goidc.Grant) error {
	return ctx.GrantManager.SaveGrant(ctx, grant)
}

func (ctx Context) SaveOpaqueToken(token *goidc.Token) error {
	return ctx.OpaqueTokenManager.SaveToken(ctx, token)
}

func (ctx Context) OpaqueToken(id string) (*goidc.Token, error) {
	return ctx.OpaqueTokenManager.Token(ctx, id)
}

func (ctx Context) SaveLogoutSession(session *goidc.LogoutSession) error {
	return ctx.LogoutManager.SaveLogoutSession(ctx, session)
}

func (ctx Context) LogoutSession(id string) (*goidc.LogoutSession, error) {
	return ctx.LogoutManager.LogoutSession(ctx, id)
}

func (ctx Context) BaseURL() string {
	return ctx.Issuer() + ctx.EndpointPrefix
}

func (ctx Context) BearerToken() (string, bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx Context) AuthorizationToken() (token string, tokenType goidc.TokenType, ok bool) {
	tokenHeader, ok := ctx.Header("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Fields(tokenHeader)
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx Context) Header(name string) (string, bool) {
	value := ctx.Request.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) RequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) WriteStatus(status int) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return
	default:
	}

	ctx.Response.WriteHeader(status)
}

// Write responds the current request writing obj as JSON.
func (ctx Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteJWT(token string, status int) error {
	return ctx.WriteJWTWithType(token, status, "application/jwt")
}

func (ctx Context) WriteJWTWithType(token string, status int, contentType string) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", contentType)
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteError(err error) {
	ctx.HandleError(err)

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		oidcErr = goidc.NewError(goidc.ErrorCodeInternalError, "internal error")
	}

	oidcErr = oidcErr.WithURI(ctx.ErrorURI)
	if err := ctx.Write(oidcErr, oidcErr.StatusCode()); err != nil {
		ctx.Response.WriteHeader(http.StatusInternalServerError)
	}
}

func (ctx Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusSeeOther) // TODO: 303 or 302?
}

func (ctx Context) WriteHTML(html string, params any) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "text/html")
	ctx.Response.Header().Set("Cache-Control", "no-cache, no-store")
	ctx.Response.Header().Set("Pragma", "no-cache")
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Response, params)
}

func (ctx Context) MediaType() string {
	ct := ctx.Request.Header.Get("Content-Type")
	return strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
}

func (ctx Context) RefreshGrantByRefreshToken(tkn string) (*goidc.Grant, error) {
	return ctx.RefreshTokenManager.GrantByRefreshToken(ctx, tkn)
}

func (ctx Context) RefreshTokenShouldIssue(c *goidc.Client, grant *goidc.Grant) bool {
	return ctx.RefreshTokenShouldIssueFunc(ctx, c, grant)
}

func (ctx Context) RefreshToken() string {
	return ctx.RefreshTokenFunc(ctx)
}

func (ctx Context) TokenOptions(grant *goidc.Grant, c *goidc.Client) goidc.TokenOptions {
	return ctx.TokenOptionsFunc(ctx, grant, c)
}

func (ctx Context) HandleGrant(grantType goidc.GrantType, grant *goidc.Grant) error {
	return ctx.HandleGrantFunc(ctx, grantType, grant)
}

func (ctx Context) HandleToken(tkn *goidc.Token, grant *goidc.Grant) error {
	return ctx.HandleTokenFunc(ctx, tkn, grant)
}

func (ctx Context) Grant(id string) (*goidc.Grant, error) {
	return ctx.GrantManager.Grant(ctx, id)
}

func (ctx Context) IDTokenClaims(grant *goidc.Grant) map[string]any {
	return ctx.IDTokenClaimsFunc(ctx, grant)
}

func (ctx Context) UserInfoClaims(grant *goidc.Grant) map[string]any {
	return ctx.UserInfoClaimsFunc(ctx, grant)
}

func (ctx Context) TokenClaims(tkn *goidc.Token, grant *goidc.Grant) map[string]any {
	return ctx.TokenClaimsFunc(ctx, tkn, grant)
}

func (ctx Context) HTTPClient() *http.Client {
	return ctx.HTTPClientFunc(ctx)
}

func (ctx Context) PairwiseSubject(sub string, c *goidc.Client) string {
	return ctx.PairwiseSubjectFunc(ctx, sub, c)
}

func (ctx Context) ClientSecret() string {
	// Client secret must be at least 64 characters, so that it can be also
	// used for symmetric encryption during, for instance, authentication with
	// client_secret_jwt.
	// For client_secret_jwt, the highest algorithm accepted in this implementation
	// is HS512 which requires a key of at least 512 bits (64 characters).
	return strutil.Random(64)
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx Context) Context() context.Context {
	if ctx.context != nil {
		return ctx.context
	}
	return ctx.Request.Context()
}

func (ctx Context) Deadline() (deadline time.Time, ok bool) {
	return ctx.Context().Deadline()
}

func (ctx Context) Done() <-chan struct{} {
	return ctx.Context().Done()
}

func (ctx Context) Err() error {
	return ctx.Context().Err()
}

func (ctx Context) Value(key any) any {
	return ctx.Context().Value(key)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx Context) JWKS() (goidc.JSONWebKeySet, error) {
	return ctx.JWKSFunc(ctx)
}

func (ctx Context) PublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) SigAlgs() ([]goidc.SignatureAlgorithm, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return nil, err
	}

	var algorithms []goidc.SignatureAlgorithm
	for _, jwk := range jwks.Keys {
		if joseutil.KeyUsage(jwk) == goidc.KeyUsageSignature {
			algorithms = append(algorithms, goidc.SignatureAlgorithm(jwk.Algorithm))
		}
	}

	return algorithms, nil
}

func (ctx Context) PublicJWK(kid string) (goidc.JSONWebKey, error) {
	key, err := ctx.JWK(kid)
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return key.Public(), nil
}

func (ctx Context) JWK(kid string) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.Key(kid)
}

// JWKByAlg searches a key that matches the signature algorithm from the JWKS.
func (ctx Context) JWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) Sign(claims any, alg goidc.SignatureAlgorithm, opts *jose.SignerOptions) (string, error) {
	if alg == goidc.SigAlgNone {
		return joseutil.Unsigned(claims, opts), nil
	}

	if ctx.SignerFunc == nil {
		jwk, err := ctx.JWKByAlg(alg)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return joseutil.Sign(claims, jose.SigningKey{Algorithm: alg, Key: jwk}, opts)
	}

	keyID, key, err := ctx.SignerFunc(ctx, alg)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: alg,
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: alg,
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) AuthnMethodAttestationJWTHTTPClient() *http.Client {
	if ctx.AuthnMethodAttestationJWTHTTPClientFunc == nil {
		return ctx.HTTPClient()
	}
	return ctx.AuthnMethodAttestationJWTHTTPClientFunc(ctx)
}
