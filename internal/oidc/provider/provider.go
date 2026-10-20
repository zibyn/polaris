package provider

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/authorize"
	"github.com/zibyn/polaris/internal/oidc/internal/client"
	"github.com/zibyn/polaris/internal/oidc/internal/discovery"
	"github.com/zibyn/polaris/internal/oidc/internal/logout"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/storage"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
	"github.com/zibyn/polaris/internal/oidc/internal/token"
	"github.com/zibyn/polaris/internal/oidc/internal/userinfo"
)

type Provider struct {
	config oidc.Configuration
}

type Config struct {
	Issuer      string
	Manager     goidc.GrantManager
	JWKS        goidc.JWKSFunc
	IDTokenAlgs []goidc.SignatureAlgorithm
}

// New creates a new openid provider.
//
// The cfg.JWKSFunc parameter provides the server's JSON Web Key Set (JWKS),
// used for signing and exposure via the JWKS endpoint.
// Typically, it should return both private and public key material.
// If private keys are unavailable or granular control over signing is required,
// cfg.JWKSFunc can be configured to return only public key material. In such cases,
// the [WithSigner] option must be provided to handle signing operations.
// For operations like signature verification, only the public key material is
// needed, which can be retrieved using cfg.JWKSFunc.
//
// cfg.IDTokenAlgs must contain at least one algorithm; the first element is
// used as the default signing algorithm. Ensure the JWKS contains keys
// supporting all declared algorithms.
//
// cfg.Manager is optional and defaults to an in-memory implementation.
// Access tokens are issued as JWTs signed with the first ID token algorithm.
func New(cfg Config, opts ...Option) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer cannot be empty")
	}

	if cfg.JWKS == nil {
		return nil, errors.New("the jwks function cannot be empty")
	}

	if len(cfg.IDTokenAlgs) == 0 {
		return nil, errors.New("at least one ID token signature algorithm must be provided")
	}

	op := &Provider{
		config: oidc.Configuration{
			GrantManager:         cfg.Manager,
			Host:                 cfg.Issuer,
			JWKSFunc:             cfg.JWKS,
			IDTokenDefaultSigAlg: cfg.IDTokenAlgs[0],
			IDTokenSigAlgs:       cfg.IDTokenAlgs,
		},
	}

	for _, opt := range opts {
		if err := opt(op); err != nil {
			return nil, err
		}
	}

	if op.config.AuthnMethodDefault != "" && !slices.Contains(op.config.AuthnMethods, op.config.AuthnMethodDefault) {
		return nil, fmt.Errorf("default authn method %q is not among the enabled authn methods", op.config.AuthnMethodDefault)
	}

	if op.config.TokenBindingRequired && !op.config.DPoPEnabled {
		return nil, errors.New("dpop must be enabled if sender constraining tokens is required")
	}

	if op.config.ConsumeJTIFunc == nil {
		slog.Warn("ConsumeJTIFunc is not configured; JTI replay protection is disabled. Configure provider.WithJTIConsumer for production use.")
	}

	inmemoryManager := storage.NewManager(defaultStorageMaxSize)

	op.config.GrantManager = nonZeroOrDefault(op.config.GrantManager, goidc.GrantManager(inmemoryManager))
	if op.config.OpaqueTokenEnabled {
		op.config.OpaqueTokenManager = nonZeroOrDefault(op.config.OpaqueTokenManager, goidc.OpaqueTokenManager(inmemoryManager))
		op.config.OpaqueTokenFunc = nonZeroOrDefault(op.config.OpaqueTokenFunc, defaultOpaqueTokenFunc)
	}

	op.config.Scopes = nonZeroOrDefault(op.config.Scopes, []goidc.Scope{goidc.ScopeOpenID})

	op.config.HTTPClientFunc = nonZeroOrDefault(op.config.HTTPClientFunc, defaultHTTPClientFunc)
	op.config.TokenOptionsFunc = nonZeroOrDefault(op.config.TokenOptionsFunc, defaultTokenOptionsFunc(op.config.IDTokenDefaultSigAlg))

	op.config.VerifyClientSecretFunc = nonZeroOrDefault(op.config.VerifyClientSecretFunc, goidc.VerifyClientSecretFunc(defaultVerifyClientSecretFunc))
	op.config.ConsumeJTIFunc = nonZeroOrDefault(op.config.ConsumeJTIFunc, goidc.ConsumeJTIFunc(defaultConsumeJTIFunc))
	op.config.HandleErrorFunc = nonZeroOrDefault(op.config.HandleErrorFunc, goidc.HandleErrorFunc(defaultHandleErrorFunc))
	op.config.HandleGrantFunc = nonZeroOrDefault(op.config.HandleGrantFunc, goidc.HandleGrantFunc(defaultHandleGrantFunc))
	op.config.HandleTokenFunc = nonZeroOrDefault(op.config.HandleTokenFunc, goidc.HandleTokenFunc(defaultHandleTokenFunc))
	op.config.IDTokenClaimsFunc = nonZeroOrDefault(op.config.IDTokenClaimsFunc, goidc.IDTokenClaimsFunc(defaultIDTokenClaimsFunc))
	op.config.UserInfoClaimsFunc = nonZeroOrDefault(op.config.UserInfoClaimsFunc, goidc.UserInfoClaimsFunc(defaultUserInfoClaimsFunc))
	op.config.TokenClaimsFunc = nonZeroOrDefault(op.config.TokenClaimsFunc, goidc.TokenClaimsFunc(defaultTokenClaimsFunc))

	op.config.SubIdentifierTypeDefault = nonZeroOrDefault(op.config.SubIdentifierTypeDefault, goidc.SubIdentifierPublic)
	op.config.SubIdentifierTypes = nonZeroOrDefault(op.config.SubIdentifierTypes, []goidc.SubIdentifierType{goidc.SubIdentifierPublic})
	if slices.Contains(op.config.SubIdentifierTypes, goidc.SubIdentifierPairwise) {
		op.config.PairwiseSubjectFunc = nonZeroOrDefault(op.config.PairwiseSubjectFunc, goidc.PairwiseSubjectFunc(defaultPairwiseSubjectFunc))
	}

	op.config.ClaimTypes = nonZeroOrDefault(op.config.ClaimTypes, []goidc.ClaimType{goidc.ClaimTypeNormal})

	op.config.IDTokenLifetimeSecs = nonZeroOrDefault(op.config.IDTokenLifetimeSecs, defaultIDTokenLifetimeSecs)

	op.config.JWKSEndpoint = nonZeroOrDefault(op.config.JWKSEndpoint, defaultEndpointJSONWebKeySet)

	op.config.TokenEndpoint = nonZeroOrDefault(op.config.TokenEndpoint, defaultEndpointToken)

	op.config.AuthorizationEndpoint = nonZeroOrDefault(op.config.AuthorizationEndpoint, defaultEndpointAuthorize)

	op.config.UserInfoEndpoint = nonZeroOrDefault(op.config.UserInfoEndpoint, defaultEndpointUserInfo)

	op.config.JWTLifetimeSecs = nonZeroOrDefault(op.config.JWTLifetimeSecs, defaultJWTLifetimeSecs)
	op.config.GrantIDFunc = nonZeroOrDefault(op.config.GrantIDFunc, defaultGrantIDFunc)
	op.config.JWTIDFunc = nonZeroOrDefault(op.config.JWTIDFunc, defaultJWTIDFunc)
	op.config.AuthSessionIDFunc = nonZeroOrDefault(op.config.AuthSessionIDFunc, defaultSessionIDFunc)

	if slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) {
		op.config.AuthManager = nonZeroOrDefault(op.config.AuthManager, goidc.AuthManager(inmemoryManager))
		if !slices.Contains(op.config.ResponseTypes, goidc.ResponseTypeCode) {
			op.config.ResponseTypes = append([]goidc.ResponseType{goidc.ResponseTypeCode}, op.config.ResponseTypes...)
		}
		op.config.AuthTimeoutSecs = nonZeroOrDefault(op.config.AuthTimeoutSecs, defaultAuthnSessionTimeoutSecs)
		op.config.AuthCodeLifetimeSecs = nonZeroOrDefault(op.config.AuthCodeLifetimeSecs, defaultAuthorizationCodeLifetimeSecs)
		op.config.AuthCodeFunc = nonZeroOrDefault(op.config.AuthCodeFunc, defaultAuthCodeFunc)
		if slices.ContainsFunc(op.config.ResponseTypes, func(rt goidc.ResponseType) bool {
			return rt.IsImplicit()
		}) {
			op.config.GrantTypes = append(op.config.GrantTypes, goidc.GrantImplicit)
		}
		responseModes := []goidc.ResponseMode{goidc.ResponseModeQuery, goidc.ResponseModeFragment}
		if slices.Contains(op.config.ResponseModes, goidc.ResponseModeFormPost) {
			responseModes = append(responseModes, goidc.ResponseModeFormPost)
		}
		op.config.ResponseModes = responseModes
	}

	op.config.AuthnMethods = nonZeroOrDefault(op.config.AuthnMethods, []goidc.AuthnMethod{goidc.AuthnMethodSecretPost})

	if op.config.TokenIntrospectionEnabled {
		op.config.TokenIntrospectionEndpoint = nonZeroOrDefault(op.config.TokenIntrospectionEndpoint, defaultEndpointTokenIntrospection)
		op.config.TokenIntrospectionIsClientAllowedFunc = nonZeroOrDefault(op.config.TokenIntrospectionIsClientAllowedFunc, goidc.IsClientAllowedTokenIntrospectionFunc(defaultTokenIntrospectionIsClientAllowedFunc))
	}

	if op.config.TokenRevocationEnabled {
		op.config.TokenRevocationEndpoint = nonZeroOrDefault(op.config.TokenRevocationEndpoint, defaultEndpointTokenRevocation)
		op.config.TokenRevocationIsClientAllowedFunc = nonZeroOrDefault(op.config.TokenRevocationIsClientAllowedFunc, goidc.IsClientAllowedFunc(defaultTokenRevocationIsClientAllowedFunc))
	}

	if slices.Contains(op.config.GrantTypes, goidc.GrantRefreshToken) {
		op.config.RefreshTokenManager = nonZeroOrDefault(op.config.RefreshTokenManager, goidc.RefreshTokenManager(inmemoryManager))
		op.config.RefreshTokenFunc = nonZeroOrDefault(op.config.RefreshTokenFunc, defaultRefreshTokenFunc)
		op.config.RefreshTokenShouldIssueFunc = nonZeroOrDefault(op.config.RefreshTokenShouldIssueFunc, goidc.RefreshTokenShouldIssueFunc(defaultRefreshTokenShouldIssueFunc))
	}

	if op.config.LogoutEnabled {
		op.config.LogoutManager = nonZeroOrDefault(op.config.LogoutManager, goidc.LogoutManager(inmemoryManager))
		op.config.LogoutEndpoint = nonZeroOrDefault(op.config.LogoutEndpoint, defaultEndpointEndSession)
		op.config.LogoutSessionTimeoutSecs = nonZeroOrDefault(op.config.LogoutSessionTimeoutSecs, defaultLogoutSessionTimeoutSecs)
		op.config.LogoutSessionIDFunc = nonZeroOrDefault(op.config.LogoutSessionIDFunc, defaultSessionIDFunc)
	}

	if op.config.RAREnabled {
		op.config.RARValidateDetailFunc = nonZeroOrDefault(op.config.RARValidateDetailFunc, goidc.RARValidateDetailFunc(defaultRARValidateDetailFunc))
		op.config.RARCompareDetailsFunc = nonZeroOrDefault(op.config.RARCompareDetailsFunc, defaultCompareAuthDetailsFunc)
	}

	return op, nil
}

func (op *Provider) Issuer() string {
	return op.config.Host
}

// Handler returns an HTTP handler with all the logic defined for the openid provider.
// This may be used to add the oidc logic to a HTTP server.
//
//	mux := http.NewServeMux()
//	mux.Handle("/", op.Handler())
func (op *Provider) Handler(middlewares ...goidc.MiddlewareFunc) http.Handler {
	mux := http.NewServeMux()
	op.RegisterRoutes(mux, middlewares...)
	return mux
}

func (op Provider) RegisterRoutes(mux *http.ServeMux, middlewares ...goidc.MiddlewareFunc) {
	middlewares = append(middlewares, cacheControlMiddleware)
	discovery.RegisterHandlers(mux, &op.config, middlewares...)
	token.RegisterHandlers(mux, &op.config, middlewares...)
	authorize.RegisterHandlers(mux, &op.config, middlewares...)
	userinfo.RegisterHandlers(mux, &op.config, middlewares...)
	logout.RegisterHandlers(mux, &op.config, middlewares...)
}

func (op *Provider) Run(address string, middlewares ...goidc.MiddlewareFunc) error {
	server := &http.Server{
		Addr:        address,
		Handler:     op.Handler(middlewares...),
		ReadTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func (op *Provider) Client(ctx context.Context, id string) (*goidc.Client, error) {
	return client.Client(oidc.NewContext(ctx, &op.config), id)
}

func (op *Provider) Introspect(ctx context.Context, tkn string) (goidc.TokenInfo, *goidc.Grant, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.Introspect(oidcCtx, tkn, nil)
}

// IDToken parses and validates an ID token issued by this provider, returning
// its claims as an [goidc.IDToken].
func (op *Provider) IDToken(ctx context.Context, idToken string) (goidc.IDToken, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.IDToken(oidcCtx, idToken)
}

// MakeToken generates a new access token based on the provided grant
// and stores the corresponding grant session and token.
func (op *Provider) MakeToken(ctx context.Context, grant *goidc.Grant) (string, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	c := &goidc.Client{ID: grant.ClientID}

	if grant.ID == "" {
		grant.ID = oidcCtx.GrantID()
	}

	if grant.CreatedAt == 0 {
		grant.CreatedAt = timeutil.TimestampNow()
	}

	if err := oidcCtx.SaveGrant(grant); err != nil {
		return "", err
	}

	_, tokenValue, err := token.Issue(oidcCtx, grant, c, nil)
	return tokenValue, err
}

// ChallengeClient authenticates the client of an authorization challenge
// request as the token endpoint would, and checks the scopes and PKCE it
// asks for, as the authorization endpoint would.
func (op *Provider) ChallengeClient(w http.ResponseWriter, r *http.Request, params goidc.AuthorizationParameters) (*goidc.Client, error) {
	ctx := oidc.NewHTTPContext(w, r, &op.config)
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return nil, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the client may not use the authorization_code grant")
	}
	for s := range strings.FieldsSeq(params.Scopes) {
		if scope, ok := ctx.Scope(s); !ok || !slices.Contains(strings.Fields(c.ScopeIDs), scope.ID) {
			return nil, goidc.NewError(goidc.ErrorCodeInvalidScope, "scope "+s+" is not allowed")
		}
	}
	if params.CodeChallenge == "" {
		if c.IsPublic() {
			return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "code_challenge is required")
		}
	} else if !slices.Contains(op.config.PKCEChallengeMethods, params.CodeChallengeMethod) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "code_challenge_method is not supported")
	}
	return c, nil
}

// IssueAuthCode completes an authorization challenge for sub: it creates the
// grant /authorize would after a login, and returns its authorization code,
// redeemable at the token endpoint without a redirect_uri.
func (op *Provider) IssueAuthCode(ctx context.Context, c *goidc.Client, sub string, params goidc.AuthorizationParameters, store map[string]any) (string, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	grant, err := token.NewGrant(oidcCtx, c, token.GrantOptions{
		Type:              goidc.GrantAuthorizationCode,
		Subject:           sub,
		ClientID:          c.ID,
		Scopes:            params.Scopes,
		AuthCode:          oidcCtx.AuthCode(),
		AuthCodeExpiresAt: timeutil.TimestampNow() + oidcCtx.AuthCodeLifetimeSecs,
		AuthParams:        params,
		Store:             store,
	})
	if err != nil {
		return "", err
	}
	return grant.AuthCode, nil
}

func (op *Provider) RevokeToken(ctx context.Context, tkn string) error {
	return token.Revoke(oidc.NewContext(ctx, &op.config), tkn, nil)
}

// nonZeroOrDefault returns the first argument "s1" if it is non-nil and non-zero.
// Otherwise, it returns the second argument "s2" as the default value.
//
// Example:
//
//	nonZeroOrDefault(42, 100) // returns 42
//	nonZeroOrDefault(0, 100)  // returns 100
//	nonZeroOrDefault("", "default") // returns "default"
func nonZeroOrDefault[T any](s1 T, s2 T) T {
	isNil := func(i any) bool {
		return i == nil
	}

	if isNil(s1) || reflect.ValueOf(s1).IsZero() {
		return s2
	}

	return s1
}

const (
	defaultStorageMaxSize                = 100
	defaultAuthnSessionTimeoutSecs       = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs           = 600
	defaultTokenLifetimeSecs             = 300
	defaultJWTLifetimeSecs               = 600
	defaultLogoutSessionTimeoutSecs      = 1800 // 30 minutes.
	defaultAuthorizationCodeLifetimeSecs = 60
	defaultEndpointJSONWebKeySet         = "/jwks"
	defaultEndpointAuthorize             = "/authorize"
	defaultEndpointToken                 = "/token"
	defaultEndpointUserInfo              = "/userinfo"
	defaultEndpointTokenIntrospection    = "/introspect"
	defaultEndpointTokenRevocation       = "/revoke"
	defaultEndpointEndSession            = "/logout"
)

func defaultTokenOptionsFunc(alg goidc.SignatureAlgorithm) goidc.TokenOptionsFunc {
	return func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(alg, defaultTokenLifetimeSecs)
	}
}

func defaultOpaqueTokenFunc(_ context.Context, _ *goidc.Grant) string {
	return strutil.Random(50)
}

func defaultRefreshTokenFunc(_ context.Context) string {
	return strutil.Random(100)
}

func defaultHTTPClientFunc(_ context.Context) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func defaultAuthCodeFunc(_ context.Context) string {
	return strutil.Random(30)
}

func defaultVerifyClientSecretFunc(_ context.Context, stored, presented string) error {
	if subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) != 1 {
		return errors.New("invalid client secret")
	}
	return nil
}

func defaultCompareAuthDetailsFunc(_ context.Context, requested, granted []goidc.AuthDetail) error {
	if !reflect.DeepEqual(requested, granted) {
		return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details")
	}
	return nil
}

func defaultConsumeJTIFunc(context.Context, string) error {
	return nil
}

func defaultTokenIntrospectionIsClientAllowedFunc(context.Context, *goidc.Client, goidc.TokenInfo) bool {
	return false
}

func defaultTokenRevocationIsClientAllowedFunc(context.Context, *goidc.Client) bool {
	return false
}

func defaultHandleErrorFunc(context.Context, error) {}

func defaultRARValidateDetailFunc(context.Context, goidc.AuthDetail) error {
	return nil
}

func defaultRefreshTokenShouldIssueFunc(context.Context, *goidc.Client, *goidc.Grant) bool {
	return true
}

func defaultHandleGrantFunc(context.Context, goidc.GrantType, *goidc.Grant) error {
	return nil
}

func defaultHandleTokenFunc(context.Context, *goidc.Token, *goidc.Grant) error {
	return nil
}

func defaultIDTokenClaimsFunc(context.Context, *goidc.Grant) map[string]any {
	return nil
}

func defaultUserInfoClaimsFunc(context.Context, *goidc.Grant) map[string]any {
	return nil
}

func defaultTokenClaimsFunc(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
	return nil
}

func defaultPairwiseSubjectFunc(_ context.Context, sub string, _ *goidc.Client) string {
	return sub
}

func defaultGrantIDFunc(_ context.Context) string {
	return rand.Text()
}

func defaultJWTIDFunc(_ context.Context) string {
	return rand.Text()
}

func defaultSessionIDFunc(_ context.Context) string {
	return rand.Text()
}

func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid caching.
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
