package authorize

import (
	"errors"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
)

func TestValidateRequest(t *testing.T) {
	newValidRequest := func(client *goidc.Client) request {
		return request{
			AuthorizationParameters: goidc.AuthorizationParameters{
				RedirectURI:  client.RedirectURIs[0],
				ResponseType: goidc.ResponseTypeCode,
				ResponseMode: goidc.ResponseModeQuery,
				Scopes:       client.ScopeIDs,
				State:        "random_state",
				Nonce:        "random_nonce",
			},
		}
	}

	tests := []struct {
		name             string
		setup            func(*testing.T) (oidc.Context, *goidc.Client, request)
		wantErr          goidc.ErrorCode
		wantRedirectErr  bool
		wantNonRedirect  bool
		wantRedirectURIs []string
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, newValidRequest(client)
			},
		},
		{
			name: "invalid response type",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ResponseTypes = nil
				return ctx, client, newValidRequest(client)
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantRedirectErr: true,
		},
		{
			name: "invalid scope",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.Scopes = "invalid_scope"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidScope,
			wantRedirectErr: true,
		},
		{
			name: "invalid redirect uri",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.RedirectURI = "https://invalid.com"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "request object not supported",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.RequestObject = "eyJhbGciOiJub25lIn0.e30."
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeRequestNotSupported,
			wantRedirectErr: true,
		},
		{
			name: "request uri not supported",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.RequestURI = "https://client.example.com/request.jwt"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeRequestURINotSupported,
			wantRedirectErr: true,
		},
		{
			name: "resource indicator",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.ResponseMode = ""
				req.Resources = []string{"https://resource.com"}
				return ctx, client, req
			},
		},
		{
			name: "resource indicator invalid resource",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				client, _ := oidctest.NewClient(t)
				req := newValidRequest(client)
				req.ResponseMode = ""
				req.Resources = []string{"https://invalid.com"}
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidTarget,
			wantRedirectErr: true,
		},
		{
			name: "redirect uri exact match",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "https://example.com/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri loopback ipv4 with port",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri loopback ipv6 with port",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://[::1]/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://[::1]:9000/callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri non loopback native app keeps exact port match",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "https://example.com:444/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri loopback not registered",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"https://example.com/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri loopback non native app",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeWeb
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "http://127.0.0.1:8080/callback"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
		{
			name: "redirect uri private scheme",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"com.example.app://callback"}
				req := newValidRequest(client)
				req.RedirectURI = "com.example.app://callback"
				return ctx, client, req
			},
		},
		{
			name: "redirect uri invalid uri",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				client.ApplicationType = goidc.ApplicationTypeNative
				client.RedirectURIs = []string{"http://127.0.0.1/callback"}
				req := newValidRequest(client)
				req.RedirectURI = "://invalid"
				return ctx, client, req
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantNonRedirect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, client, req := test.setup(t)

			err := validateRequest(ctx, req, client)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				if test.wantRedirectErr {
					var redirectErr redirectionError
					if !errors.As(err, &redirectErr) {
						t.Fatalf("expected redirected error, got %T", err)
					}
					if redirectErr.Code() != test.wantErr {
						t.Fatalf("code = %s, want %s", redirectErr.Code(), test.wantErr)
					}
				}

				if test.wantNonRedirect {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) {
						t.Fatalf("expected OIDC error, got %T", err)
					}
					if oidcErr.Code != test.wantErr {
						t.Fatalf("code = %s, want %s", oidcErr.Code, test.wantErr)
					}
				}
			}

			if test.wantRedirectURIs != nil && !slices.Equal(client.RedirectURIs, test.wantRedirectURIs) {
				t.Fatalf("RedirectURIs = %v, want %v", client.RedirectURIs, test.wantRedirectURIs)
			}
		})
	}
}
