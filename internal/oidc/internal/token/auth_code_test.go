package token

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
)

func TestGenerateAuthCodeToken(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
		tb.Helper()

		c, secret := oidctest.NewClient(tb)
		ctx := oidctest.NewContext(tb)
		ctx.AuthManager = oidctest.Manager(tb, ctx)
		ctx.AuthCodeLifetimeSecs = 60
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		now := timeutil.TimestampNow()
		grant := &goidc.Grant{
			ClientID: c.ID,
			Scopes:   goidc.ScopeOpenID.ID,
			AuthParams: goidc.AuthorizationParameters{
				Scopes:      goidc.ScopeOpenID.ID,
				RedirectURI: c.RedirectURIs[0],
			},
			AuthCode:          "random_authz_code",
			AuthCodeExpiresAt: now + ctx.AuthCodeLifetimeSecs,
			Subject:           "user_id",
			CreatedAt:         now,
			Store:             make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			tb.Errorf("error while creating the session: %v", err)
		}

		req := request{
			grantType:   goidc.GrantAuthorizationCode,
			redirectURI: c.RedirectURIs[0],
			code:        grant.AuthCode,
		}

		return ctx, req, c, grant
	}

	tests := []struct {
		name            string
		setup           func() (oidc.Context, request, *goidc.Client, *goidc.Grant)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		validate        func(*testing.T, oidc.Context, response, *goidc.Client, *goidc.Grant)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.AuthCodeConsumedAt == 0 {
					t.Fatal("expected auth code to be marked as consumed")
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       grant.Subject,
					"client_id": grant.ClientID,
					"scope":     grant.Scopes,
					"grant_id":  grant.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
				if resp.RefreshToken != grant.RefreshToken {
					t.Errorf("RefreshToken = %q, want %q", resp.RefreshToken, grant.RefreshToken)
				}
			},
		},
		{
			name: "auth details",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				grant.AuthDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, g *goidc.Grant) {
				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantAuthDetails := []any{
					map[string]any{
						"type":         "type1",
						"random_claim": "random_value",
					},
					map[string]any{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(claims["authorization_details"], wantAuthDetails); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth details subset",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				grant.AuthDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				req.authDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				wantAuthDetails := []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
				}

				if diff := cmp.Diff(resp.AuthorizationDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "resource indicators subset",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				grant.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				req.resources = []string{"https://resource1.com", "https://resource2.com"}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				wantResources := goidc.Resources{"https://resource1.com", "https://resource2.com"}

				if diff := cmp.Diff(resp.Resources, wantResources); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantAud := []any{"https://resource1.com", "https://resource2.com"}
				if diff := cmp.Diff(claims["aud"], wantAud); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "consumed auth code",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.AuthCodeConsumedAt = timeutil.TimestampNow()
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			wantWrappedErr:  "the authorization code has already been redeemed",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "pkce",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				grant.AuthParams.CodeChallenge = "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98"
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.AuthCodeConsumedAt == 0 {
					t.Fatal("expected auth code to be marked as consumed")
				}
			},
		},
		{
			name: "pkce sha256 valid 2",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				grant.AuthParams.CodeChallenge = "yQ0Wg2MXS83nBOaS3yit-n-xEaEw5LQ8TlhtX_2NkLw"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = "42d92ec716da149b8c0a553d5cbbdc5fd474625cdffe7335d643105b"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].AuthCodeConsumedAt == 0 {
					t.Fatal("expected auth code to be marked as consumed")
				}
			},
		},
		{
			name: "pkce sha256 wrong verifier",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				grant.AuthParams.CodeChallenge = "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "pkce sha256 verifier as challenge",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				grant.AuthParams.CodeChallenge = "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "pkce sha256 empty verifier",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				grant.AuthParams.CodeChallenge = "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = ""
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "pkce plain valid",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodPlain
				grant.AuthParams.CodeChallenge = "0123456789abcdef0123456789abcdef0123456789a"
				grant.AuthParams.CodeChallengeMethod = goidc.CodeChallengeMethodPlain
				req.codeVerifier = "0123456789abcdef0123456789abcdef0123456789a"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].AuthCodeConsumedAt == 0 {
					t.Fatal("expected auth code to be marked as consumed")
				}
			},
		},
		{
			name: "pkce downgrade is mitigated",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.PKCEEnabled = true
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
				ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
				req.codeVerifier = "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98"
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "no binding",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.JWKThumbprint != "" {
					t.Errorf("JWKThumbprint = %q, want empty", grant.JWKThumbprint)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				if _, ok := claims["cnf"]; ok {
					t.Error("expected no cnf claim in unbound token")
				}
			},
		},
		{
			name: "dpop binding",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.DPoPEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/token"

				dpopJWT, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{Method: http.MethodPost, URI: ctx.Host + "/token"})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				grant.JWKThumbprint = thumbprint
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.JWKThumbprint == "" {
					t.Fatal("expected JWK thumbprint to be set on grant")
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				cnf, ok := claims["cnf"].(map[string]any)
				if !ok {
					t.Fatal("expected cnf claim in token")
				}
				if cnf["jkt"] != grant.JWKThumbprint {
					t.Errorf("cnf.jkt = %v, want %v", cnf["jkt"], grant.JWKThumbprint)
				}
			},
		},
		{
			name: "dpop binding key mismatch",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.DPoPEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/token"

				// Use one key for the grant thumbprint, another for the DPoP header.
				_, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{Method: http.MethodPost, URI: ctx.Host + "/token"})
				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{Method: http.MethodPost, URI: ctx.Host + "/token"})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				grant.JWKThumbprint = thumbprint
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "dpop binding missing header",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.DPoPEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}

				_, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{Method: http.MethodPost, URI: ctx.Host + "/token"})
				grant.JWKThumbprint = thumbprint
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "dpop required by config but not sent",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.DPoPEnabled = true
				ctx.DPoPRequired = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "dpop required by client but not sent",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.DPoPEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
				c.DPoPTokenBindingRequired = true
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing auth code",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.code = ""
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "code is required",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "invalid client auth",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "expired auth code",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.AuthCodeExpiresAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			wantWrappedErr:  "the authorization code has expired",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "wrong redirect uri",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.redirectURI = "https://wrong.example.com/callback"
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			wantWrappedErr:  "the redirect_uri does not match the authorization code",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "client mismatch",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.ClientID = "different_client"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			wantWrappedErr:  "the authorization code belongs to a different client",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "client lacks grant type",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			wantWrappedErr:  "the client is not allowed to use the authorization_code grant type",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "scope narrowing",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.Scopes = "openid " + oidctest.Scope1.ID
				req.scopes = goidc.ScopeOpenID.ID
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				if resp.Scopes != goidc.ScopeOpenID.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, goidc.ScopeOpenID.ID)
				}
			},
		},
		{
			name: "invalid scope narrowing",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = "scope_not_granted"
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, c, grant := test.setup()

			// When.
			resp, err := generateToken(ctx, req)

			// Then.
			if gotErr, wantErr := err != nil, test.wantErr != ""; gotErr != wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, test.wantErr)
			}

			if test.wantErr != "" {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c, grant)
			}
		})
	}
}
