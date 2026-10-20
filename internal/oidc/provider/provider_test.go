package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
	"github.com/zibyn/polaris/internal/oidc/internal/storage"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
)

func TestNew(t *testing.T) {
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	tests := []struct {
		name    string
		setup   func() (Config, []Option)
		want    oidc.Configuration
		ignores []string
	}{
		{
			name: "default",
			setup: func() (Config, []Option) {
				return Config{
					Issuer:      issuer,
					JWKS:        jwksFunc,
					IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				}, nil
			},
			want: oidc.Configuration{
				Host:                     issuer,
				Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
				ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
				SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
				SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
				JWKSEndpoint:             defaultEndpointJSONWebKeySet,
				TokenEndpoint:            defaultEndpointToken,
				AuthorizationEndpoint:    defaultEndpointAuthorize,
				UserInfoEndpoint:         defaultEndpointUserInfo,
				AuthnMethods:             []goidc.AuthnMethod{goidc.AuthnMethodSecretPost},
				IDTokenDefaultSigAlg:     goidc.SigAlgRS256,
				IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
				JWTLifetimeSecs:          defaultJWTLifetimeSecs,
			},
			ignores: []string{
				"GrantManager",
				"OpaqueTokenManager",
				"JWKSFunc",
				"AuthSessionIDFunc",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"ConsumeJTIFunc",
				"TokenIntrospectionIsClientAllowedFunc",
				"TokenRevocationIsClientAllowedFunc",
				"HandleErrorFunc",
				"RARValidateDetailFunc",
				"RefreshTokenShouldIssueFunc",
				"HandleGrantFunc",
				"HandleTokenFunc",
				"IDTokenClaimsFunc",
				"UserInfoClaimsFunc",
				"TokenClaimsFunc",
				"PairwiseSubjectFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
		{
			name: "with options",
			setup: func() (Config, []Option) {
				manager := storage.NewManager(100)
				return Config{
					Issuer:      issuer,
					JWKS:        jwksFunc,
					IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				}, []Option{
					WithAuthCodeGrant(AuthCodeGrantConfig{
						Manager: manager,
						ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode, goidc.ResponseTypeToken,
							goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken, goidc.ResponseTypeCodeAndIDToken,
							goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken},
					},
						WithFormPostResponseMode(),
					),
					WithPrivateKeyJWTAuthn(goidc.SigAlgRS256),
					WithSecretJWTAuthn(goidc.SigAlgHS256),
					WithTokenIntrospection(nil),
					WithTokenRevocation(nil),
					WithUserInfoSignatureAlgs(goidc.SigAlgPS256),
					WithUserInfoEncryption(
						[]goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
						[]goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
					),
				}
			},
			want: oidc.Configuration{
				Host:                     issuer,
				Scopes:                   []goidc.Scope{goidc.ScopeOpenID},
				AuthTimeoutSecs:          defaultAuthnSessionTimeoutSecs,
				ClaimTypes:               []goidc.ClaimType{goidc.ClaimTypeNormal},
				SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
				SubIdentifierTypes:       []goidc.SubIdentifierType{goidc.SubIdentifierPublic},
				JWKSEndpoint:             defaultEndpointJSONWebKeySet,
				TokenEndpoint:            defaultEndpointToken,
				AuthorizationEndpoint:    defaultEndpointAuthorize,
				UserInfoEndpoint:         defaultEndpointUserInfo,
				UserInfoDefaultSigAlg:    goidc.SigAlgPS256,
				UserInfoSigAlgs:          []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
				IDTokenDefaultSigAlg:     goidc.SigAlgRS256,
				IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				IDTokenLifetimeSecs:      defaultIDTokenLifetimeSecs,
				JWTLifetimeSecs:          defaultJWTLifetimeSecs,
				GrantTypes: []goidc.GrantType{
					goidc.GrantAuthorizationCode,
					goidc.GrantImplicit,
				},
				ResponseTypes: []goidc.ResponseType{
					goidc.ResponseTypeCode,
					goidc.ResponseTypeToken,
					goidc.ResponseTypeIDToken,
					goidc.ResponseTypeIDTokenAndToken,
					goidc.ResponseTypeCodeAndIDToken,
					goidc.ResponseTypeCodeAndToken,
					goidc.ResponseTypeCodeAndIDTokenAndToken,
				},
				AuthnMethods:                    []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
				AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
				AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
				ResponseModes: []goidc.ResponseMode{
					goidc.ResponseModeQuery,
					goidc.ResponseModeFragment,
					goidc.ResponseModeFormPost,
				},
				TokenIntrospectionEnabled:  true,
				TokenIntrospectionEndpoint: defaultEndpointTokenIntrospection,
				TokenRevocationEnabled:     true,
				TokenRevocationEndpoint:    defaultEndpointTokenRevocation,
				UserInfoEncEnabled:         true,
				UserInfoKeyEncAlgs:         []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
				UserInfoContentEncAlgs:     []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128CBCHS256},
				AuthCodeLifetimeSecs:       60,
			},
			ignores: []string{
				"AuthManager",
				"AuthCodeFunc",
				"AuthSessionIDFunc",
				"GrantManager",
				"OpaqueTokenManager",
				"GrantIDFunc",
				"JWTIDFunc",
				"OpaqueTokenFunc",
				"RefreshTokenFunc",
				"HTTPClientFunc",
				"JWKSFunc",
				"ConsumeJTIFunc",
				"TokenIntrospectionIsClientAllowedFunc",
				"TokenRevocationIsClientAllowedFunc",
				"HandleErrorFunc",
				"RARValidateDetailFunc",
				"RefreshTokenShouldIssueFunc",
				"HandleGrantFunc",
				"HandleTokenFunc",
				"IDTokenClaimsFunc",
				"UserInfoClaimsFunc",
				"TokenClaimsFunc",
				"PairwiseSubjectFunc",
				"TokenOptionsFunc",
				"VerifyClientSecretFunc",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, opts := test.setup()

			op, err := New(cfg, opts...)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(
				op.config,
				test.want,
				cmpopts.IgnoreFields(oidc.Configuration{}, test.ignores...),
				cmpopts.IgnoreFields(goidc.Scope{}, "Matches"),
			); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDefaultHTTPClientFuncDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	resp, err := defaultHTTPClientFunc(context.Background()).Get(source.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Fatal("default HTTP client followed redirect")
	}
}

func TestNew_ValidationErrors(t *testing.T) {
	issuer := "https://example.com"
	var jwksFunc goidc.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{Issuer: issuer, JWKS: jwksFunc, IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256}}, test.opts...)
			if err == nil {
				t.Fatal("New() error = nil, want non-nil")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("New() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

func TestMakeToken(t *testing.T) {
	// Given.
	issuer := "https://example.com"
	jwk := oidctest.PrivateRS256JWK(t, "test_key", goidc.KeyUsageSignature)
	op, _ := New(
		Config{
			Issuer: issuer,
			JWKS: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
			},
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
		WithTokenOptions(func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
			return goidc.NewJWTTokenOptions(goidc.SigAlgRS256, 60)
		}),
	)

	ctx := context.Background()
	oidcCtx := oidc.NewContext(ctx, &op.config)
	grant := &goidc.Grant{
		ClientID: issuer,
		Subject:  issuer,
		Scopes:   "openid",
	}

	// When.
	tkn, err := op.MakeToken(ctx, grant)

	// Then.
	if err != nil {
		t.Error(err)
	}

	grantSessions := oidctest.Grants(t, oidcCtx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]
	wantedSession := goidc.Grant{
		ID:        grantSession.ID,
		CreatedAt: grantSession.CreatedAt,
		Subject:   issuer,
		ClientID:  issuer,
		Scopes:    "openid",
	}
	if diff := cmp.Diff(
		*grantSession,
		wantedSession,
		cmpopts.EquateApprox(0, 1),
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tkn, jwk)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       issuer,
		"sub":       issuer,
		"client_id": issuer,
		"scope":     grant.Scopes,
		"exp":       float64(now + 60),
		"iat":       float64(now),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti" || k == "grant_id"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}
