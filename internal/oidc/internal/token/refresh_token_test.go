package token

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
)

const testRefreshToken = "random_refresh_token"

func TestGenerateRefreshToken(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
		tb.Helper()

		c, secret := oidctest.NewClient(tb)

		ctx := oidctest.NewContext(tb)
		ctx.RefreshTokenManager = oidctest.Manager(tb, ctx)
		ctx.RefreshTokenFunc = func(ctx context.Context) string { return strutil.Random(30) }
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		now := timeutil.TimestampNow()
		grant := &goidc.Grant{
			RefreshToken:          testRefreshToken,
			RefreshTokenExpiresAt: now + 60,
			CreatedAt:             now,
			Subject:               "random_user",
			ClientID:              c.ID,
			Scopes:                c.ScopeIDs,
			Store:                 make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			tb.Fatalf("error while creating the grant: %v", err)
		}

		req := request{
			grantType:    goidc.GrantRefreshToken,
			refreshToken: testRefreshToken,
		}

		return ctx, req, c, grant
	}

	tests := []struct {
		name            string
		setup           func() (oidc.Context, request, *goidc.Client, *goidc.Grant)
		wantErr         goidc.ErrorCode
		wantDescription string
		validateErr     func(*testing.T, error, *goidc.Client, *goidc.Grant)
		validate        func(*testing.T, oidc.Context, response, *goidc.Client, *goidc.Grant)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client, g *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.RefreshToken != testRefreshToken {
					t.Errorf("grant.RefreshToken = %q, want %q", grant.RefreshToken, testRefreshToken)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       g.Subject,
					"client_id": c.ID,
					"scope":     grant.Scopes,
					"grant_id":  grant.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}

				if resp.RefreshToken != "" {
					t.Errorf("resp.RefreshToken = %q, want empty", resp.RefreshToken)
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
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
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
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
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
			name: "revoked grant",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.RevokedAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			validateErr: func(t *testing.T, err error, _ *goidc.Client, _ *goidc.Grant) {
				t.Helper()

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				want := "the grant associated to the refresh token was revoked"
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != want {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, want)
				}
			},
			validate: func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "expired refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.RefreshTokenExpiresAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			validateErr: func(t *testing.T, err error, _ *goidc.Client, grant *goidc.Grant) {
				t.Helper()

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				want := "the refresh token expired at " + strconv.Itoa(grant.RefreshTokenExpiresAt)
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != want {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, want)
				}
			},
			validate: func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "non-expiring refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.RefreshTokenExpiresAt = 0
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
				if grants[0].RefreshTokenExpiresAt != 0 {
					t.Fatalf("grant.RefreshTokenExpiresAt = %d, want 0", grants[0].RefreshTokenExpiresAt)
				}

				if resp.AccessToken == "" {
					t.Fatal("expected access token to be issued")
				}
			},
		},
		{
			name: "scope narrowing",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = goidc.ScopeOpenID.ID
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, g *goidc.Grant) {
				if resp.Scopes != goidc.ScopeOpenID.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, goidc.ScopeOpenID.ID)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Scopes != g.Scopes {
					t.Errorf("grant.Scopes = %q, want %q", grants[0].Scopes, g.Scopes)
				}
			},
		},
		{
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = "not_granted_scope"
				return ctx, req, c, grant
			},
			wantErr:  goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "rotation enabled",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.RefreshTokenRotationEnabled = true
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				if resp.RefreshToken == "" {
					t.Fatal("expected a new refresh token")
				}
				if resp.RefreshToken == testRefreshToken {
					t.Fatal("expected rotated refresh token to differ from original")
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RefreshToken != resp.RefreshToken {
					t.Errorf("grant.RefreshToken = %q, want %q", grants[0].RefreshToken, resp.RefreshToken)
				}
			},
		},
		{
			name: "rotation enabled clears expiry when lifetime is zero",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.RefreshTokenRotationEnabled = true
				ctx.RefreshTokenLifetimeSecs = 0
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				if resp.RefreshToken == "" {
					t.Fatal("expected a new refresh token")
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RefreshTokenExpiresAt != 0 {
					t.Fatalf("grant.RefreshTokenExpiresAt = %d, want 0", grants[0].RefreshTokenExpiresAt)
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
			validateErr: func(t *testing.T, err error, c *goidc.Client, grant *goidc.Grant) {
				t.Helper()

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				want := "the refresh token belongs to client \"" + grant.ClientID + "\", not \"" + c.ID + "\""
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != want {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, want)
				}
			},
			validate: func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "client lacks grant type",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			validateErr: func(t *testing.T, err error, _ *goidc.Client, _ *goidc.Grant) {
				t.Helper()

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				want := "the client is not allowed to use the refresh_token grant type"
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != want {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, want)
				}
			},
			validate: func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "missing refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.refreshToken = ""
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			validate:        func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
		{
			name: "invalid refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.refreshToken = "invalid_refresh_token"
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid grant",
			validate:        func(t *testing.T, _ oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, c, grant := test.setup()

			resp, err := generateToken(ctx, req)

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
				if test.validateErr != nil {
					test.validateErr(t, err, c, grant)
				}
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c, grant)
			}
		})
	}
}
