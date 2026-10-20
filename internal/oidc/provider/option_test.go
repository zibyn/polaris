package provider

import (
	"context"
	"crypto"
	"net/http"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
	"github.com/zibyn/polaris/internal/oidc/internal/storage"
)

func TestWithPathPrefix(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPathPrefix("/auth")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			EndpointPrefix: "/auth",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWKSEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWKSEndpoint("/jwks")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWKSEndpoint: "/jwks",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenEndpoint("/token")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenEndpoint: "/token",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizeEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthorizeEndpoint("/authorize")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			AuthorizationEndpoint: "/authorize",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEndpoint("/userinfo")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoEndpoint: "/userinfo",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospectionEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenIntrospectionEndpoint("/introspect")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenIntrospectionEndpoint: "/introspect",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestTokenRevocationEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, WithTokenRevocationEndpoint("/revoke"))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenRevocationEnabled:  true,
			TokenRevocationEndpoint: "/revoke",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClientSecretVerifier(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var gotStored string
	var gotPresented string
	f := func(_ context.Context, stored, presented string) error {
		gotStored = stored
		gotPresented = presented
		return nil
	}

	// When.
	err := WithClientSecretVerifier(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.VerifyClientSecretFunc == nil {
		t.Fatal("VerifyClientSecretFunc must be set")
	}

	if err := p.config.VerifyClientSecretFunc(context.Background(), "stored", "presented"); err != nil {
		t.Fatalf("unexpected verifier error: %v", err)
	}
	if gotStored != "stored" || gotPresented != "presented" {
		t.Fatalf("verifier inputs = (%q, %q), want (%q, %q)", gotStored, gotPresented, "stored", "presented")
	}
}

func TestWithClaims(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaims("claim_one", "claim_two")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			Claims:     []string{"claim_one", "claim_two"},
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeNormal},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaimTypes(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaimTypes(goidc.ClaimTypeDistributed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeDistributed},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoSignatureAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoSignatureAlgs(goidc.SigAlgRS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoDefaultSigAlg: goidc.SigAlgRS256,
			UserInfoSigAlgs:       []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
	)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoEncEnabled:     true,
			UserInfoKeyEncAlgs:     []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
			UserInfoContentEncAlgs: []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryptionValidation(t *testing.T) {
	tests := []struct {
		name        string
		keyAlgs     []goidc.KeyEncryptionAlgorithm
		contentAlgs []goidc.ContentEncryptionAlgorithm
		wantErr     string
	}{
		{
			name:        "requires key encryption algorithm",
			contentAlgs: []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
			wantErr:     "at least one key encryption algorithm is required for user info encryption",
		},
		{
			name:    "requires content encryption algorithm",
			keyAlgs: []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
			wantErr: "at least one content encryption algorithm is required for user info encryption",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := WithUserInfoEncryption(test.keyAlgs, test.contentAlgs)(&Provider{})
			if err == nil {
				t.Fatal("WithUserInfoEncryption() error = nil, want non-nil")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("WithUserInfoEncryption() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

func TestWithIDTokenEncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
	)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenEncEnabled:     true,
			IDTokenKeyEncAlgs:     []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
			IDTokenContentEncAlgs: []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenEncryptionValidation(t *testing.T) {
	tests := []struct {
		name        string
		keyAlgs     []goidc.KeyEncryptionAlgorithm
		contentAlgs []goidc.ContentEncryptionAlgorithm
		wantErr     string
	}{
		{
			name:        "requires key encryption algorithm",
			contentAlgs: []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM},
			wantErr:     "at least one key encryption algorithm is required for ID token encryption",
		},
		{
			name:    "requires content encryption algorithm",
			keyAlgs: []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP},
			wantErr: "at least one content encryption algorithm is required for ID token encryption",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := WithIDTokenEncryption(test.keyAlgs, test.contentAlgs)(&Provider{})
			if err == nil {
				t.Fatal("WithIDTokenEncryption() error = nil, want non-nil")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("WithIDTokenEncryption() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

func TestWithLocalhostRedirectURIs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLocalhostRedirectURIs()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			LocalhostRedirectURIEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthCodeGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(1)

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		Manager:       manager,
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthManager != manager {
		t.Error("AuthManager not set")
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) {
		t.Error("GrantAuthorizationCode not added")
	}

	if !slices.Contains(p.config.ResponseTypes, goidc.ResponseTypeCode) {
		t.Error("ResponseTypeCode not added")
	}
}

func TestWithRefreshTokenGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(1)

	// When.
	err := WithRefreshTokenGrant(manager)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantRefreshToken) {
		t.Error("GrantRefreshToken not added")
	}

	if p.config.RefreshTokenManager != manager {
		t.Error("RefreshTokenManager not set")
	}
}

func TestWithRefreshTokenFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	tokenFunc := func(context.Context) string { return "refresh_token" }

	// When.
	err := WithRefreshTokenFunc(tokenFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.RefreshTokenFunc == nil {
		t.Error("WithRefreshTokenFunc cannot be nil")
	}
}

func TestWithClientCredentialsGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClientCredentialsGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			GrantTypes: []goidc.GrantType{goidc.GrantClientCredentials},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenRotation(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithRefreshTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			RefreshTokenRotationEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithOpenIDScopeRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDScopeRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenOptions(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var tokenOpts goidc.TokenOptionsFunc = func(
		_ context.Context,
		_ *goidc.Grant,
		_ *goidc.Client,
	) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(60)
	}

	// When.
	err := WithTokenOptions(tokenOpts)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.TokenOptionsFunc == nil {
		t.Error("TokenOptionsFunc cannot be nil")
	}
}

func TestWithGrantHandler(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var grantHandler goidc.HandleGrantFunc = func(context.Context, goidc.GrantType, *goidc.Grant) error {
		return nil
	}

	// When.
	err := WithGrantHandler(grantHandler)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleGrantFunc == nil {
		t.Error("HandleGrantFunc cannot be nil")
	}
}

func TestWithScopes(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When
	err := WithScopes(goidc.ScopeEmail)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.config.Scopes) != 2 {
		t.Error("there should be only two scopes")
	}
}

func TestWithAssertionLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWTLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIssuerResponseParameter(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIssuerResponseParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IssuerRespParamEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithFormPostResponseMode(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithFormPostResponseMode()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResponseModes: []goidc.ResponseMode{goidc.ResponseModeFormPost},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizationDetails(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithRAR([]goidc.AuthDetailType{"detail_type"})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.RAREnabled {
		t.Errorf("auth details must be enabled")
	}

	if p.config.RARDetailTypes == nil {
		t.Error("auth detail types should be set")
	}

}

func TestWithDPoP(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgPS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPEnabled: true,
			DPoPSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoPRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgPS256}, WithDPoPRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPEnabled:  true,
			DPoPRequired: true,
			DPoPSigAlgs:  []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenBindingRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenBindingRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospection(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenIntrospection(nil)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenIntrospectionEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenRevocation(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var isAllowed goidc.IsClientAllowedFunc = func(context.Context, *goidc.Client) bool {
		return true
	}

	// When.
	err := WithTokenRevocation(isAllowed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}

	if p.config.TokenRevocationIsClientAllowedFunc == nil {
		t.Error("TokenRevocationIsClientAllowedFunc not set")
	}
}

func TestTokenRevocationRevokeGrantOnAccessToken(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, WithTokenRevocationRevokeGrantOnAccessToken())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}

	if !p.config.TokenRevocationRevokeGrantOnAccessTokenEnabled {
		t.Error("TokenRevocationRevokeGrantOnAccessTokenEnabled should be true")
	}
}

func TestWithPKCE(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE_MultipleMethods(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256, goidc.CodeChallengeMethodPlain})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodSHA256,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256, goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestPKCERequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}, WithPKCERequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCERequired:               true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithACRs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithACRs("0")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ACRs: []goidc.ACR{"0"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDisplayValues(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDisplayValues(goidc.DisplayValuePage)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DisplayValues: []goidc.DisplayValue{goidc.DisplayValuePage},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthenticationSessionTimeout(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthSessionLifetime(10)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			AuthTimeoutSecs: 10,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithStaticClients(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	c1, _ := oidctest.NewClient(t)
	c2, _ := oidctest.NewClient(t)

	// When.
	err := WithStaticClients(c1, c2)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			StaticClients: []*goidc.Client{c1, c2},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{}), cmpopts.IgnoreUnexported(goidc.Client{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthPolicies(t *testing.T) {
	p := &Provider{}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	err := WithAuthPolicies(policy)(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(p.config.AuthPolicies, []goidc.AuthnPolicy{policy}); diff != "" {
		t.Error(diff)
	}
}

func TestWithErrorRenderer(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var renderFunc goidc.RenderErrorFunc = func(
		w http.ResponseWriter,
		r *http.Request,
		err error,
	) error {
		return nil
	}

	// When.
	err := WithErrorRenderer(renderFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.RenderErrorFunc == nil {
		t.Error("RenderErrorFunc cannot be nil")
	}
}

func TestWithNotifyErrorFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var handleErrorFunc goidc.HandleErrorFunc = func(
		ctx context.Context,
		err error,
	) {
	}

	// When.
	err := WithErrorHandler(handleErrorFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleErrorFunc == nil {
		t.Error("HandleErrorFunc cannot be nil")
	}
}

func TestWithJTIConsumer(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var consumeJTIFunc goidc.ConsumeJTIFunc = func(ctx context.Context, s string) error {
		return nil
	}

	// When.
	err := WithJTIConsumer(consumeJTIFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.ConsumeJTIFunc == nil {
		t.Error("ConsumeJTIFunc cannot be nil")
	}
}

func TestWithResourceIndicators(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicators([]string{"https://resource.com"})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResourceIndicatorsEnabled: true,
			ResourceIndicators:        []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithResourceIndicatorsRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicators([]string{"https://resource.com"}, WithResourceIndicatorsRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResourceIndicatorsEnabled:  true,
			ResourceIndicatorsRequired: true,
			ResourceIndicators:         []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithHTTPClientFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithHTTPClientFunc(func(ctx context.Context) *http.Client {
		return &http.Client{}
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HTTPClientFunc == nil {
		t.Error("HTTPClientFunc cannot be nil")
	}
}

func TestWithGrantID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "session_id" }

	// When.
	err := WithGrantIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.GrantIDFunc == nil {
		t.Error("GrantIDFunc cannot be nil")
	}
}

func TestOpaqueTokenFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	tokenFunc := func(context.Context, *goidc.Grant) string { return "opaque_token" }

	// When.
	err := WithTokenOptions(nil, WithOpaqueTokenFunc(tokenFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.OpaqueTokenFunc == nil {
		t.Error("WithOpaqueTokenFunc cannot be nil")
	}
}

func TestWithJWTLeewayTime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTLeewayTime(30)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWTLeewayTimeSecs: 30,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaimsParameter(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaimsParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ClaimsParamEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSubjectIdentifiers(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	pairwiseFunc := func(ctx context.Context, sub string, c *goidc.Client) string {
		return "pairwise_sub"
	}

	// When.
	err := WithSubjectIdentifiers(
		[]goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise},
		WithPairwiseSubjectFunc(pairwiseFunc),
	)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.SubIdentifierTypeDefault != goidc.SubIdentifierPublic {
		t.Errorf("SubIdentifierTypeDefault = %q, want %q", p.config.SubIdentifierTypeDefault, goidc.SubIdentifierPublic)
	}
	if diff := cmp.Diff(p.config.SubIdentifierTypes, []goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise}); diff != "" {
		t.Error(diff)
	}
	if p.config.PairwiseSubjectFunc == nil {
		t.Error("PairwiseSubjectFunc cannot be nil")
	}
}

func TestWithSigner(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	signerFunc := func(ctx context.Context, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		return "kid", nil, nil
	}

	// When.
	err := WithSigner(signerFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.SignerFunc == nil {
		t.Error("SignerFunc cannot be nil")
	}
}

func TestWithErrorURI(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithErrorURI("https://example.com/errors")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ErrorURI: "https://example.com/errors",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthnSessionIDFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "authn_session_id" }

	// When.
	err := WithAuthnSessionIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthSessionIDFunc == nil {
		t.Error("AuthnSessionGenerateIDFunc cannot be nil")
	}
}

func TestWithJWTID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "jwt_id" }

	// When.
	err := WithJWTIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.JWTIDFunc == nil {
		t.Error("JWTIDFunc cannot be nil")
	}
}

func TestAuthCodeFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	codeFunc := func(context.Context) string { return "auth_code" }

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	}, WithAuthCodeFunc(codeFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthCodeFunc == nil {
		t.Error("WithAuthCodeFunc cannot be nil")
	}
}

func TestAuthCodeLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	}, WithAuthCodeLifetime(90))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthCodeLifetimeSecs != 90 {
		t.Fatalf("AuthCodeLifetimeSecs = %d, want %d", p.config.AuthCodeLifetimeSecs, 90)
	}
}

func TestWithLogout(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(10)
	handleFunc := func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) error {
		return nil
	}

	// When.
	err := WithLogout(LogoutConfig{
		Manager:    manager,
		HandleFunc: handleFunc,
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutManager != manager {
		t.Error("invalid logout session manager")
	}

	if p.config.HandleDefaultPostLogoutFunc == nil {
		t.Error("HandleDefaultPostLogoutFunc cannot be nil")
	}
}

func TestLogoutPolicies(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	policy := goidc.NewLogoutPolicy(
		"policy",
		func(_ *http.Request, _ *goidc.LogoutSession) bool {
			return true
		},
		func(_ http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) (goidc.Status, error) {
			return goidc.StatusSuccess, nil
		},
	)

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutPolicies(policy))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.config.LogoutPolicies) != 1 {
		t.Fatalf("got %d logout policies, want 1", len(p.config.LogoutPolicies))
	}

	if p.config.LogoutPolicies[0].ID != policy.ID {
		t.Fatalf("got logout policy %q, want %q", p.config.LogoutPolicies[0].ID, policy.ID)
	}
}

func TestLogoutSessionTimeoutSecs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutSessionTimeoutSecs(600))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutSessionTimeoutSecs != 600 {
		t.Errorf("WithLogoutSessionTimeoutSecs = %d, want 600", p.config.LogoutSessionTimeoutSecs)
	}
}

func TestLogoutEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutEndpoint("/logout"))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutEndpoint != "/logout" {
		t.Errorf("WithLogoutEndpoint = %q, want %q", p.config.LogoutEndpoint, "/logout")
	}
}

func TestLogoutSessionIDFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "logout_session_id" }

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutSessionIDFunc(idFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutSessionIDFunc == nil {
		t.Error("WithLogoutSessionIDFunc cannot be nil")
	}
}

func TestWithNoneAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithNoneAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodNone}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretPostAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretPostAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodSecretPost}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretBasicAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretBasicAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodSecretBasic}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithPrivateKeyJWTAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithPrivateKeyJWTAuthn(goidc.SigAlgRS256, goidc.SigAlgPS256)(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantAlgs := []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgPS256}
	if diff := cmp.Diff(p.config.AuthnMethodPrivateKeyJWTSigAlgs, wantAlgs); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretJWTAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretJWTAuthn(goidc.SigAlgHS256)(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodSecretJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantAlgs := []goidc.SignatureAlgorithm{goidc.SigAlgHS256}
	if diff := cmp.Diff(p.config.AuthnMethodSecretJWTSigAlgs, wantAlgs); diff != "" {
		t.Error(diff)
	}
}

func TestWithAttestationJWTAuthn(t *testing.T) {
	p := &Provider{}
	issuer := goidc.AttestationIssuer{Issuer: "https://attester.example.com", JWKSURI: "https://attester.example.com/jwks"}
	if err := WithAttestationJWTAuthn([]goidc.AttestationIssuer{issuer})(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodAttestationJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantIssuers := []goidc.AttestationIssuer{issuer}
	if diff := cmp.Diff(p.config.AuthnMethodAttestationJWTIssuers, wantIssuers); diff != "" {
		t.Error(diff)
	}
}

func TestWithAttestationJWTAuthnValidation(t *testing.T) {
	tests := []struct {
		name    string
		issuers []goidc.AttestationIssuer
		wantErr string
	}{
		{
			name:    "requires issuers",
			wantErr: "at least one attestation issuer is required",
		},
		{
			name: "requires issuer",
			issuers: []goidc.AttestationIssuer{
				{JWKSURI: "https://attester.example.com/jwks"},
			},
			wantErr: "attestation issuer cannot be empty",
		},
		{
			name: "requires key source",
			issuers: []goidc.AttestationIssuer{
				{Issuer: "https://attester.example.com"},
			},
			wantErr: "attestation issuer \"https://attester.example.com\" requires either JWKSURI or JWKSFunc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := WithAttestationJWTAuthn(test.issuers)(&Provider{})
			if err == nil {
				t.Fatal("WithAttestationJWTAuthn() error = nil, want non-nil")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("WithAttestationJWTAuthn() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

func TestWithDPoP_NoneAlgorithm(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgNone})(p)

	// Then.
	if err == nil {
		t.Error("expected error for 'none' algorithm")
	}
}

func TestWithScopes_OpenIDScopeAlreadyPresent(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithScopes(goidc.ScopeOpenID, goidc.ScopeEmail)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// OpenID scope should not be duplicated.
	openIDCount := 0
	for _, s := range p.config.Scopes {
		if s.ID == goidc.ScopeOpenID.ID {
			openIDCount++
		}
	}
	if openIDCount != 1 {
		t.Errorf("expected 1 openid scope, got %d", openIDCount)
	}
}
