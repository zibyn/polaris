package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
	"github.com/zibyn/polaris/internal/oidc/internal/storage"
)

func TestTokenAuthnSigAlgs(t *testing.T) {
	tests := []struct {
		name string
		ctx  oidc.Context
		want []goidc.SignatureAlgorithm
	}{
		{
			name: "no methods",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{},
			},
			want: nil,
		},
		{
			name: "private key jwt",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					AuthnMethods:                    []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
					AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		},
		{
			name: "secret jwt",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					AuthnMethods:                []goidc.AuthnMethod{goidc.AuthnMethodSecretJWT},
					AuthnMethodSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
		},
		{
			name: "both methods",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					AuthnMethods:                    []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
					AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
					AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.SigAlgPS256, goidc.SigAlgHS256},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.ctx.TokenAuthnSigAlgs()
			if diff := cmp.Diff(test.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	ctx := newContext()
	policies := []goidc.AuthnPolicy{
		goidc.NewPolicy("policy_1", nil, nil),
	}

	policy := ctx.Policy(policies, "policy_1")
	if policy.ID != "policy_1" {
		t.Fatalf("Policy().ID = %q, want %q", policy.ID, "policy_1")
	}
}

func TestLogoutPolicyHelpers(t *testing.T) {
	t.Run("logout policy by id", func(t *testing.T) {
		ctx := newContext()
		ctx.LogoutPolicies = []goidc.LogoutPolicy{
			goidc.NewLogoutPolicy("logout_1", nil, nil),
		}

		policy := ctx.LogoutPolicy("logout_1")
		if policy.ID != "logout_1" {
			t.Fatalf("LogoutPolicy().ID = %q, want %q", policy.ID, "logout_1")
		}
	})

	t.Run("missing logout policy returns not found behavior", func(t *testing.T) {
		ctx := newContext()
		policy := ctx.LogoutPolicy("missing")
		status, err := policy.Logout(nil, nil, nil)
		if status != goidc.StatusFailure {
			t.Fatalf("LogoutPolicy().Logout() status = %q, want %q", status, goidc.StatusFailure)
		}
		if !errors.Is(err, goidc.ErrNotFound) {
			t.Fatalf("LogoutPolicy().Logout() error = %v, want %v", err, goidc.ErrNotFound)
		}
	})

}

func TestBaseURL(t *testing.T) {
	ctx := newContext()
	ctx.Host = "https://example.com"
	ctx.EndpointPrefix = "/auth"

	if got := ctx.BaseURL(); got != "https://example.com/auth" {
		t.Fatalf("BaseURL() = %q, want %q", got, "https://example.com/auth")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		validate func(*testing.T, string, bool)
	}{
		{
			name:   "present",
			header: "Bearer access_token",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if !ok {
					t.Fatal("BearerToken() did not find the token")
				}
				if token != "access_token" {
					t.Fatalf("BearerToken() = %q, want %q", token, "access_token")
				}
			},
		},
		{
			name:   "missing",
			header: "",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("BearerToken() found unexpected token %q", token)
				}
			},
		},
		{
			name:   "not bearer",
			header: "DPoP token",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("BearerToken() found unexpected token %q", token)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			if test.header != "" {
				ctx.Request.Header.Set("Authorization", test.header)
			}

			token, ok := ctx.BearerToken()
			test.validate(t, token, ok)
		})
	}
}

func TestAuthorizationToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		validate func(*testing.T, string, goidc.TokenType, bool)
	}{
		{
			name:   "bearer token",
			header: "Bearer access_token",
			validate: func(t *testing.T, token string, tokenType goidc.TokenType, ok bool) {
				t.Helper()
				if !ok {
					t.Fatal("AuthorizationToken() did not find the token")
				}
				if token != "access_token" {
					t.Fatalf("AuthorizationToken() token = %q, want %q", token, "access_token")
				}
				if tokenType != goidc.TokenTypeBearer {
					t.Fatalf("AuthorizationToken() type = %q, want %q", tokenType, goidc.TokenTypeBearer)
				}
			},
		},
		{
			name:   "missing",
			header: "",
			validate: func(t *testing.T, token string, tokenType goidc.TokenType, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("AuthorizationToken() found unexpected token %q of type %q", token, tokenType)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			if test.header != "" {
				ctx.Request.Header.Set("Authorization", test.header)
			}

			token, tokenType, ok := ctx.AuthorizationToken()
			test.validate(t, token, tokenType, ok)
		})
	}
}

func TestHeader(t *testing.T) {
	ctx := newContext()
	ctx.Request.Header.Set("Test-Header", "test_value")

	header, ok := ctx.Header("Test-Header")
	if !ok {
		t.Fatal("Header() did not find the header")
	}
	if header != "test_value" {
		t.Fatalf("Header() = %q, want %q", header, "test_value")
	}
}

func TestSigAlgs(t *testing.T) {
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	encryptionKey := oidctest.PrivatePS256JWK(t, "encryption_key", goidc.KeyUsageEncryption)
	ctx := newContext()
	ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey, encryptionKey}}, nil
	}

	algs, err := ctx.SigAlgs()
	if err != nil {
		t.Fatalf("SigAlgs() error = %v", err)
	}

	want := []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	if diff := cmp.Diff(want, algs); diff != "" {
		t.Fatal(diff)
	}
}

func TestJWKSHelpers(t *testing.T) {
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	ctx := newContext()
	ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}, nil
	}

	t.Run("public jwks", func(t *testing.T) {
		publicJWKS, err := ctx.PublicJWKS()
		if err != nil {
			t.Fatalf("PublicJWKS() error = %v", err)
		}
		if len(publicJWKS.Keys) != 1 {
			t.Fatalf("len(PublicJWKS().Keys) = %d, want 1", len(publicJWKS.Keys))
		}
		if publicJWKS.Keys[0].KeyID != signingKey.KeyID {
			t.Fatalf("PublicJWKS().Keys[0].KeyID = %q, want %q", publicJWKS.Keys[0].KeyID, signingKey.KeyID)
		}
		if !publicJWKS.Keys[0].IsPublic() {
			t.Fatal("PublicJWKS() returned a non-public key")
		}
	})

	t.Run("public jwk", func(t *testing.T) {
		publicJWK, err := ctx.PublicJWK("signing_key")
		if err != nil {
			t.Fatalf("PublicJWK() error = %v", err)
		}
		if publicJWK.KeyID != signingKey.KeyID {
			t.Fatalf("PublicJWK().KeyID = %q, want %q", publicJWK.KeyID, signingKey.KeyID)
		}
		if !publicJWK.IsPublic() {
			t.Fatal("PublicJWK() returned a non-public key")
		}
	})

	t.Run("private jwk", func(t *testing.T) {
		privateJWK, err := ctx.JWK("signing_key")
		if err != nil {
			t.Fatalf("JWK() error = %v", err)
		}
		if privateJWK.KeyID != signingKey.KeyID {
			t.Fatalf("JWK().KeyID = %q, want %q", privateJWK.KeyID, signingKey.KeyID)
		}
		if privateJWK.IsPublic() {
			t.Fatal("JWK() returned a public key")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := ctx.JWK("missing")
		if err == nil {
			t.Fatal("JWK() error = nil, want non-nil")
		}
	})
}

func TestTokenAndPolicyHooks(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, oidc.Context)
	}{
		{
			name: "token introspection client allowed",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}
				info := goidc.TokenInfo{}

				if ctx.TokenIntrospectionIsClientAllowed(client, info) {
					t.Fatal("TokenIntrospectionIsClientAllowed() = true, want false by default")
				}

				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return true
				}
				if !ctx.TokenIntrospectionIsClientAllowed(client, info) {
					t.Fatal("TokenIntrospectionIsClientAllowed() = false, want true")
				}
			},
		},
		{
			name: "token revocation client allowed",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}

				if ctx.TokenRevocationIsClientAllowed(client) {
					t.Fatal("TokenRevocationIsClientAllowed() = true, want false by default")
				}

				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return true
				}
				if !ctx.TokenRevocationIsClientAllowed(client) {
					t.Fatal("TokenRevocationIsClientAllowed() = false, want true")
				}
			},
		},
		{
			name: "validate initial access token",
			run: func(t *testing.T, ctx oidc.Context) {

			},
		},
		{
			name: "check jti",
			run: func(t *testing.T, ctx oidc.Context) {
				ctx.ConsumeJTIFunc = func(context.Context, string) error {
					return nil
				}
				if err := ctx.ConsumeJTI("jti"); err != nil {
					t.Fatalf("ConsumeJTI() error = %v", err)
				}

				ctx.ConsumeJTIFunc = func(context.Context, string) error {
					return errors.New("error")
				}
				if err := ctx.ConsumeJTI("jti"); err == nil {
					t.Fatal("ConsumeJTI() error = nil, want non-nil")
				}
			},
		},
		{
			name: "render error",
			run: func(t *testing.T, ctx oidc.Context) {
				err := errors.New("error")
				if got := ctx.RenderError(err); !errors.Is(got, err) {
					t.Fatalf("RenderError() = %v, want %v", got, err)
				}

				ctx.RenderErrorFunc = func(http.ResponseWriter, *http.Request, error) error {
					return nil
				}
				if err := ctx.RenderError(errors.New("error")); err != nil {
					t.Fatalf("RenderError() error = %v", err)
				}
			},
		},
		{
			name: "rar compare auth details",
			run: func(t *testing.T, ctx oidc.Context) {
				called := false
				ctx.RARCompareDetailsFunc = func(_ context.Context, requested, granted []goidc.AuthDetail) error {
					called = true
					if requested != nil || granted != nil {
						t.Fatal("RARCompareAuthDetails() passed unexpected values")
					}
					return nil
				}
				if err := ctx.RARCompareAuthDetails(nil, nil); err != nil {
					t.Fatalf("RARCompareAuthDetails() error = %v", err)
				}
				if !called {
					t.Fatal("RARCompareAuthDetails() did not call RARCompareDetailsFunc")
				}
			},
		},
		{
			name: "refresh token should issue",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}
				grant := &goidc.Grant{}

				if !ctx.RefreshTokenShouldIssue(client, grant) {
					t.Fatal("RefreshTokenShouldIssue() = false, want true by default")
				}

				ctx.RefreshTokenShouldIssueFunc = func(context.Context, *goidc.Client, *goidc.Grant) bool {
					return false
				}
				if ctx.RefreshTokenShouldIssue(client, grant) {
					t.Fatal("RefreshTokenShouldIssue() = true, want false")
				}
			},
		},
		{
			name: "handle grant",
			run: func(t *testing.T, ctx oidc.Context) {
				if err := ctx.HandleGrant(goidc.GrantClientCredentials, &goidc.Grant{}); err != nil {
					t.Fatalf("HandleGrant() error = %v", err)
				}

				ctx.HandleGrantFunc = func(context.Context, goidc.GrantType, *goidc.Grant) error {
					return errors.New("error")
				}
				if err := ctx.HandleGrant(goidc.GrantClientCredentials, &goidc.Grant{}); err == nil {
					t.Fatal("HandleGrant() error = nil, want non-nil")
				}
			},
		},
		{
			name: "http client",
			run: func(t *testing.T, ctx oidc.Context) {
				custom := &http.Client{}
				ctx.HTTPClientFunc = func(context.Context) *http.Client {
					return custom
				}
				if got := ctx.HTTPClient(); got != custom {
					t.Fatal("HTTPClient() did not return the configured client")
				}
			},
		},
		{
			name: "pairwise subject",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{
					ClientMeta: goidc.ClientMeta{
						SubIdentifierType:   goidc.SubIdentifierPairwise,
						SectorIdentifierURI: "https://example.com",
					},
				}

				if got := ctx.PairwiseSubject("sub", client); got != "sub" {
					t.Fatalf("PairwiseSubject() = %q, want %q", got, "sub")
				}

				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}
				if got := ctx.PairwiseSubject("random_sub", client); got != "example.com_random_sub" {
					t.Fatalf("PairwiseSubject() = %q, want %q", got, "example.com_random_sub")
				}
			},
		},
		{
			name: "generated values delegate to funcs",
			run: func(t *testing.T, ctx oidc.Context) {
				grant := &goidc.Grant{ID: "grant_id"}
				ctx.GrantIDFunc = func(context.Context) string { return "grant" }
				ctx.JWTIDFunc = func(context.Context) string { return "jwt" }
				ctx.AuthCodeFunc = func(context.Context) string { return "code" }
				ctx.RefreshTokenFunc = func(context.Context) string { return "refresh" }
				ctx.OpaqueTokenFunc = func(context.Context, *goidc.Grant) string { return "opaque_" + grant.ID }

				if got := ctx.GrantID(); got != "grant" {
					t.Fatalf("GrantID() = %q, want %q", got, "grant")
				}
				if got := ctx.JWTID(); got != "jwt" {
					t.Fatalf("JWTID() = %q, want %q", got, "jwt")
				}
				if got := ctx.AuthCode(); got != "code" {
					t.Fatalf("AuthCode() = %q, want %q", got, "code")
				}
				if got := ctx.RefreshToken(); got != "refresh" {
					t.Fatalf("RefreshToken() = %q, want %q", got, "refresh")
				}
				if got := ctx.OpaqueTokenValue(grant); got != "opaque_grant_id" {
					t.Fatalf("OpaqueTokenValue() = %q, want %q", got, "opaque_grant_id")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, oidctest.NewContext(t))
		})
	}
}

func TestManagerDelegates(t *testing.T) {
	t.Run("auth and par sessions", func(t *testing.T) {
		ctx := oidctest.NewContext(t)
		manager := storage.NewManager(100)
		ctx.AuthManager = manager

		session := &goidc.AuthnSession{
			ID:        "session_id",
			CreatedAt: 1,
		}
		if err := ctx.AuthSaveSession(session); err != nil {
			t.Fatalf("AuthSaveSession() error = %v", err)
		}

		got, err := ctx.AuthSession(session.ID)
		if err != nil {
			t.Fatalf("AuthSession() error = %v", err)
		}
		if got.ID != session.ID {
			t.Fatalf("AuthSession().ID = %q, want %q", got.ID, session.ID)
		}

		if err != nil {
			t.Fatalf("PARSessionByPushedAuthReqID() error = %v", err)
		}

	})

	t.Run("tokens and grants", func(t *testing.T) {
		ctx := oidctest.NewContext(t)
		manager := storage.NewManager(100)
		ctx.GrantManager = manager
		ctx.RefreshTokenManager = manager
		ctx.OpaqueTokenManager = manager

		grant := &goidc.Grant{
			ID:           "grant_id",
			RefreshToken: "refresh_token",
			CreatedAt:    1,
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("SaveGrant() error = %v", err)
		}

		gotGrant, err := ctx.Grant(grant.ID)
		if err != nil {
			t.Fatalf("Grant() error = %v", err)
		}
		if gotGrant.ID != grant.ID {
			t.Fatalf("Grant().ID = %q, want %q", gotGrant.ID, grant.ID)
		}

		gotGrant, err = ctx.RefreshGrantByRefreshToken(grant.RefreshToken)
		if err != nil {
			t.Fatalf("RefreshGrantByRefreshToken() error = %v", err)
		}
		if gotGrant.ID != grant.ID {
			t.Fatalf("RefreshGrantByRefreshToken().ID = %q, want %q", gotGrant.ID, grant.ID)
		}

		token := &goidc.Token{ID: "token_id", GrantID: grant.ID}
		if err := ctx.SaveOpaqueToken(token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		gotToken, err := ctx.OpaqueToken(token.ID)
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if gotToken.ID != token.ID {
			t.Fatalf("Token().ID = %q, want %q", gotToken.ID, token.ID)
		}

	})

	t.Run("logout sessions", func(t *testing.T) {
		ctx := oidctest.NewContext(t)
		manager := storage.NewManager(100)
		ctx.LogoutManager = manager

		session := &goidc.LogoutSession{ID: "logout_session", CreatedAt: 1}
		if err := ctx.SaveLogoutSession(session); err != nil {
			t.Fatalf("SaveLogoutSession() error = %v", err)
		}

		got, err := ctx.LogoutSession(session.ID)
		if err != nil {
			t.Fatalf("LogoutSession() error = %v", err)
		}
		if got.ID != session.ID {
			t.Fatalf("LogoutSession().ID = %q, want %q", got.ID, session.ID)
		}

	})
}

func TestHTTPClientFallbacks(t *testing.T) {
	ctx := newContext()
	baseClient := &http.Client{}
	ctx.HTTPClientFunc = func(context.Context) *http.Client {
		return baseClient
	}

	if got := ctx.HTTPClient(); got != baseClient {
		t.Fatal("HTTPClient() did not return the configured client")
	}

}

func TestScopeAndHandler(t *testing.T) {
	t.Run("scope matches", func(t *testing.T) {
		ctx := newContext()
		ctx.Scopes = []goidc.Scope{goidc.NewScope("scope1"), goidc.NewScope(goidc.ScopeOpenID.ID)}

		scope, ok := ctx.Scope("scope1")
		if !ok {
			t.Fatal("Scope() = false, want true")
		}
		if scope.ID != "scope1" {
			t.Fatalf("Scope().ID = %q, want %q", scope.ID, "scope1")
		}

		if _, ok := ctx.Scope("missing"); ok {
			t.Fatal("Scope() found unexpected scope")
		}
	})

	t.Run("handler wraps request in oidc context", func(t *testing.T) {
		config := &oidc.Configuration{}
		called := false
		handler := oidc.Handler(config, func(ctx oidc.Context) {
			called = true
			if ctx.Configuration != config {
				t.Fatal("Handler() did not pass the configuration through")
			}
			ctx.WriteStatus(http.StatusNoContent)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		handler(rec, req)

		if !called {
			t.Fatal("Handler() did not execute")
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})
}

func TestContextMethods(t *testing.T) {
	type contextKey struct{}
	key := contextKey{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key, "value"))
	t.Cleanup(cancel)

	ctx := oidc.NewContext(parent, &oidc.Configuration{})

	if got := ctx.Value(key); got != "value" {
		t.Fatalf("Value() = %v, want %q", got, "value")
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("Deadline() ok = true, want false")
	}
	if ctx.Err() != nil {
		t.Fatalf("Err() = %v, want nil before cancel", ctx.Err())
	}

	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Done() channel was not closed after cancel")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Err() = %v, want %v", ctx.Err(), context.Canceled)
	}

	t.Run("falls back to request context", func(t *testing.T) {
		reqCtx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		ctx := oidc.Context{
			Configuration: &oidc.Configuration{},
			Request:       httptest.NewRequest(http.MethodGet, "https://example.com", nil).WithContext(reqCtx),
			Response:      httptest.NewRecorder(),
		}
		if got := ctx.Context(); got != reqCtx {
			t.Fatal("Context() did not fall back to the request context")
		}
	})
}

func TestSimpleHelpers(t *testing.T) {
	t.Run("grant by auth code", func(t *testing.T) {
		ctx := oidctest.NewContext(t)
		manager := storage.NewManager(100)
		ctx.AuthManager = manager
		ctx.GrantManager = manager

		grant := &goidc.Grant{ID: "grant_id", AuthCode: "auth_code", CreatedAt: 1}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("SaveGrant() error = %v", err)
		}

		got, err := ctx.GrantByAuthCode(grant.AuthCode)
		if err != nil {
			t.Fatalf("GrantByAuthCode() error = %v", err)
		}
		if got.ID != grant.ID {
			t.Fatalf("GrantByAuthCode().ID = %q, want %q", got.ID, grant.ID)
		}
	})

	t.Run("delegates and hooks", func(t *testing.T) {
		ctx := oidctest.NewContext(t)
		client := &goidc.Client{ID: "client_id"}
		grant := &goidc.Grant{ID: "grant_id"}
		token := &goidc.Token{ID: "token_id"}
		logoutSession := &goidc.LogoutSession{ID: "logout_id"}
		authDetail := goidc.AuthDetail{"type": "payment"}

		calledVerify := false
		ctx.VerifyClientSecretFunc = func(_ context.Context, stored, presented string) error {
			calledVerify = true
			if stored != "stored" || presented != "presented" {
				t.Fatalf("VerifyClientSecret() got %q/%q", stored, presented)
			}
			return nil
		}
		if err := ctx.VerifyClientSecret("stored", "presented"); err != nil {
			t.Fatalf("VerifyClientSecret() error = %v", err)
		}
		if !calledVerify {
			t.Fatal("VerifyClientSecret() did not call VerifyClientSecretFunc")
		}

		ctx.Host = "https://example.com"
		ctx.TokenEndpoint = "/token"
		ctx.Request = httptest.NewRequest(http.MethodPost, "/path?query=1", nil)
		if got := ctx.TokenURL(); got != "https://example.com/token" {
			t.Fatalf("TokenURL() = %q, want %q", got, "https://example.com/token")
		}
		if got := ctx.RequestURL(); got != "https://example.com/path?query=1" {
			t.Fatalf("RequestURL() = %q, want %q", got, "https://example.com/path?query=1")
		}
		if got := ctx.RequestMethod(); got != http.MethodPost {
			t.Fatalf("RequestMethod() = %q, want %q", got, http.MethodPost)
		}

		if err := ctx.RARValidateDetail(authDetail); err != nil {
			t.Fatalf("RARValidateDetail() default error = %v", err)
		}
		ctx.RARValidateDetailFunc = func(_ context.Context, got goidc.AuthDetail) error {
			if got["type"] != authDetail["type"] {
				t.Fatalf("RARValidateDetail() detail = %v, want %v", got["type"], authDetail["type"])
			}
			return errors.New("invalid detail")
		}
		if err := ctx.RARValidateDetail(authDetail); err == nil {
			t.Fatal("RARValidateDetail() error = nil, want non-nil")
		}

		calledDefaultPostLogout := false
		ctx.HandleDefaultPostLogoutFunc = func(_ http.ResponseWriter, _ *http.Request, got *goidc.LogoutSession) error {
			calledDefaultPostLogout = true
			if got.ID != logoutSession.ID {
				t.Fatalf("HandleDefaultPostLogout() session = %q, want %q", got.ID, logoutSession.ID)
			}
			return nil
		}
		if err := ctx.HandleDefaultPostLogout(logoutSession); err != nil {
			t.Fatalf("HandleDefaultPostLogout() error = %v", err)
		}
		if !calledDefaultPostLogout {
			t.Fatal("HandleDefaultPostLogout() did not call HandleDefaultPostLogoutFunc")
		}

		ctx.LogoutSessionIDFunc = func(context.Context) string { return "logout_session_id" }
		ctx.AuthSessionIDFunc = func(context.Context) string { return "authn_session_id" }
		if got := ctx.LogoutSessionID(); got != "logout_session_id" {
			t.Fatalf("LogoutSessionID() = %q, want %q", got, "logout_session_id")
		}
		if got := ctx.AuthnSessionID(); got != "authn_session_id" {
			t.Fatalf("AuthnSessionID() = %q, want %q", got, "authn_session_id")
		}

		opts := goidc.TokenOptions{LifetimeSecs: 123, Format: goidc.TokenFormatJWT}
		ctx.TokenOptionsFunc = func(_ context.Context, gotGrant *goidc.Grant, gotClient *goidc.Client) goidc.TokenOptions {
			if gotGrant.ID != grant.ID || gotClient.ID != client.ID {
				t.Fatal("TokenOptions() received unexpected grant or client")
			}
			return opts
		}
		if diff := cmp.Diff(opts, ctx.TokenOptions(grant, client)); diff != "" {
			t.Fatal(diff)
		}

		if err := ctx.HandleToken(token, grant); err != nil {
			t.Fatalf("HandleToken() default error = %v", err)
		}
		ctx.HandleTokenFunc = func(_ context.Context, gotToken *goidc.Token, gotGrant *goidc.Grant) error {
			if gotToken.ID != token.ID || gotGrant.ID != grant.ID {
				t.Fatal("HandleToken() received unexpected token or grant")
			}
			return errors.New("handle token error")
		}
		if err := ctx.HandleToken(token, grant); err == nil {
			t.Fatal("HandleToken() error = nil, want non-nil")
		}

		idClaims := map[string]any{"sub": "subject"}
		userInfoClaims := map[string]any{"name": "user"}
		tokenClaims := map[string]any{"scope": "openid"}
		ctx.IDTokenClaimsFunc = func(_ context.Context, got *goidc.Grant) map[string]any {
			if got.ID != grant.ID {
				t.Fatal("IDTokenClaims() received unexpected grant")
			}
			return idClaims
		}
		ctx.UserInfoClaimsFunc = func(_ context.Context, got *goidc.Grant) map[string]any {
			if got.ID != grant.ID {
				t.Fatal("UserInfoClaims() received unexpected grant")
			}
			return userInfoClaims
		}
		ctx.TokenClaimsFunc = func(_ context.Context, gotToken *goidc.Token, gotGrant *goidc.Grant) map[string]any {
			if gotToken.ID != token.ID || gotGrant.ID != grant.ID {
				t.Fatal("TokenClaims() received unexpected token or grant")
			}
			return tokenClaims
		}
		if diff := cmp.Diff(idClaims, ctx.IDTokenClaims(grant)); diff != "" {
			t.Fatal(diff)
		}
		if diff := cmp.Diff(userInfoClaims, ctx.UserInfoClaims(grant)); diff != "" {
			t.Fatal(diff)
		}
		if diff := cmp.Diff(tokenClaims, ctx.TokenClaims(token, grant)); diff != "" {
			t.Fatal(diff)
		}

		if got := ctx.ClientSecret(); len(got) != 64 {
			t.Fatalf("len(ClientSecret()) = %d, want 64", len(got))
		}
	})
}

func TestHTTPResponses(t *testing.T) {
	t.Run("write status", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		ctx.WriteStatus(http.StatusAccepted)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("WriteStatus() status = %d, want %d", rec.Code, http.StatusAccepted)
		}
	})

	t.Run("write json", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		if err := ctx.Write(map[string]string{"key": "value"}, http.StatusCreated); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("Write() status = %d, want %d", rec.Code, http.StatusCreated)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("Write() content type = %q, want %q", got, "application/json")
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if body["key"] != "value" {
			t.Fatalf("body[key] = %q, want %q", body["key"], "value")
		}
	})

	t.Run("write jwt", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		if err := ctx.WriteJWT("token", http.StatusOK); err != nil {
			t.Fatalf("WriteJWT() error = %v", err)
		}
		if rec.Body.String() != "token" {
			t.Fatalf("WriteJWT() body = %q, want %q", rec.Body.String(), "token")
		}
		if got := rec.Header().Get("Content-Type"); got != "application/jwt" {
			t.Fatalf("WriteJWT() content type = %q, want %q", got, "application/jwt")
		}
	})

	t.Run("write jwt with custom type", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		if err := ctx.WriteJWTWithType("token", http.StatusAccepted, "application/test+jwt"); err != nil {
			t.Fatalf("WriteJWTWithType() error = %v", err)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/test+jwt" {
			t.Fatalf("WriteJWTWithType() content type = %q, want %q", got, "application/test+jwt")
		}
	})

	t.Run("write error uses oidc error", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		ctx.ErrorURI = "https://example.com/errors"
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("WriteError() status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"error":"invalid_request"`) {
			t.Fatalf("WriteError() body = %q, want invalid_request", body)
		}
		if !strings.Contains(body, `"error_uri":"https://example.com/errors"`) {
			t.Fatalf("WriteError() body = %q, want error_uri", body)
		}
	})

	t.Run("write error wraps non oidc error", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		ctx.WriteError(errors.New("boom"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("WriteError() status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rec.Body.String(), `"error":"internal_error"`) {
			t.Fatalf("WriteError() body = %q, want internal_error", rec.Body.String())
		}
	})

	t.Run("redirect", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		ctx.Redirect("https://example.com/callback")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("Redirect() status = %d, want %d", rec.Code, http.StatusSeeOther)
		}
		if got := rec.Header().Get("Location"); got != "https://example.com/callback" {
			t.Fatalf("Redirect() location = %q, want %q", got, "https://example.com/callback")
		}
	})

	t.Run("write html", func(t *testing.T) {
		ctx := newContext()
		rec := httptest.NewRecorder()
		ctx.Response = rec
		if err := ctx.WriteHTML("<p>{{.Value}}</p>", map[string]string{"Value": "hello"}); err != nil {
			t.Fatalf("WriteHTML() error = %v", err)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/html" {
			t.Fatalf("WriteHTML() content type = %q, want %q", got, "text/html")
		}
		if rec.Body.String() != "<p>hello</p>" {
			t.Fatalf("WriteHTML() body = %q, want %q", rec.Body.String(), "<p>hello</p>")
		}
	})

	t.Run("media type", func(t *testing.T) {
		ctx := newContext()
		ctx.Request.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
		if got := ctx.MediaType(); got != "application/json" {
			t.Fatalf("MediaType() = %q, want %q", got, "application/json")
		}
	})
}

func TestSign(t *testing.T) {
	ctx := oidctest.NewContext(t)
	jwks, err := ctx.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	jwk := jwks.Keys[0]

	jws, err := ctx.Sign(map[string]any{"claim": "value"}, goidc.SignatureAlgorithm(jwk.Algorithm), nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.SigAlgPS256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned() error = %v", err)
	}

	var claims map[string]any
	if err := parsedJWS.Claims(jwk.Public().Key, &claims); err != nil {
		t.Fatalf("parsedJWS.Claims() error = %v", err)
	}
	if claims["claim"] != "value" {
		t.Fatalf("claims[claim] = %v, want %q", claims["claim"], "value")
	}
}

func TestSignWithSigner(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			SignerFunc: func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
				return "random_key_id", testSigner{signer: signingKey}, nil
			},
		},
	}

	jws, err := ctx.Sign(map[string]any{goidc.ClaimSubject: "random@email.com"}, goidc.SigAlgRS256, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.SigAlgRS256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned() error = %v", err)
	}

	var claims map[string]any
	if err := parsedJWS.Claims(signingKey.Public(), &claims); err != nil {
		t.Fatalf("parsedJWS.Claims() error = %v", err)
	}
	if claims[goidc.ClaimSubject] != "random@email.com" {
		t.Fatalf("claims[sub] = %v, want %q", claims[goidc.ClaimSubject], "random@email.com")
	}
}

func newContext() oidc.Context {
	return oidc.Context{
		Configuration: &oidc.Configuration{
			TokenIntrospectionIsClientAllowedFunc: func(context.Context, *goidc.Client, goidc.TokenInfo) bool {
				return false
			},
			TokenRevocationIsClientAllowedFunc: func(context.Context, *goidc.Client) bool {
				return false
			},
			HandleErrorFunc: func(context.Context, error) {},
			RARValidateDetailFunc: func(context.Context, goidc.AuthDetail) error {
				return nil
			},
			RefreshTokenShouldIssueFunc: func(context.Context, *goidc.Client, *goidc.Grant) bool {
				return true
			},
			HandleGrantFunc: func(context.Context, goidc.GrantType, *goidc.Grant) error {
				return nil
			},
			HandleTokenFunc: func(context.Context, *goidc.Token, *goidc.Grant) error {
				return nil
			},
			IDTokenClaimsFunc: func(context.Context, *goidc.Grant) map[string]any {
				return nil
			},
			UserInfoClaimsFunc: func(context.Context, *goidc.Grant) map[string]any {
				return nil
			},
			TokenClaimsFunc: func(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
				return nil
			},
			PairwiseSubjectFunc: func(_ context.Context, sub string, _ *goidc.Client) string {
				return sub
			},
		},
		Request:  httptest.NewRequest(http.MethodGet, "https://example.com", nil),
		Response: httptest.NewRecorder(),
	}
}

type testSigner struct {
	signer *rsa.PrivateKey
}

func (s testSigner) Public() crypto.PublicKey {
	return s.signer.PublicKey
}

func (s testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(rand, digest, opts)
}
