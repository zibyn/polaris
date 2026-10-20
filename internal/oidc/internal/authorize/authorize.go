package authorize

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/client"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
	"github.com/zibyn/polaris/internal/oidc/internal/token"
)

func initAuth(ctx oidc.Context, req request) error {
	if req.ClientID == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", errors.New("client_id is required"))
	}

	c, err := client.Client(ctx, req.ClientID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", fmt.Errorf("could not load the client: %w", err))
	}

	// Check that the client is allowed to call the authorization endpoint.
	if !slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the client is not allowed to use the authorization endpoint grant types"))
	}

	as, err := func() (*goidc.AuthnSession, error) {
		if err := validateRequest(ctx, req, c); err != nil {
			return nil, err
		}
		return newAuthnSession(ctx, req.AuthorizationParameters, c), nil
	}()
	if err != nil {
		return redirectError(ctx, err, c)
	}

	var policy goidc.AuthnPolicy
	for _, candidate := range ctx.AuthPolicies {
		if candidate.Setup(ctx.Request, as, c) {
			policy = candidate
			break
		}
	}
	if policy.ID == "" {
		return redirectError(ctx, wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", as.AuthorizationParameters,
			errors.New("no authentication policy is available for the authorization request")), c)
	}

	as.PolicyID = policy.ID
	as.ExpiresAt = timeutil.TimestampNow() + ctx.AuthTimeoutSecs
	if as.IDTokenHint != "" {
		// The ID token hint was already validated during request validation.
		idTkn, _ := token.IDToken(ctx, as.IDTokenHint)
		as.IDTokenHintClaims = &idTkn
	}

	if err := authenticate(ctx, as, c); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func continueAuth(ctx oidc.Context, id string) error {
	as, err := ctx.AuthSession(id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the authentication session was not found"))
		}
		return fmt.Errorf("could not load the authentication session: %w", err)
	}

	if timeutil.TimestampNow() >= as.ExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the authentication session has expired"))
	}

	// TODO: Review this.
	if as.ResponseMode.IsJSON() && ctx.RequestMethod() != http.MethodPost {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("json response mode requires an HTTP POST callback request"))
	}

	c, err := client.Client(ctx, as.ClientID)
	if err != nil {
		return fmt.Errorf("could not load the client for the authentication session: %w", err)
	}

	if oauthErr := authenticate(ctx, as, c); oauthErr != nil {
		return redirectError(ctx, oauthErr, c)
	}

	return nil
}

func authenticate(ctx oidc.Context, as *goidc.AuthnSession, c *goidc.Client) error {
	// If the policy ID is missing, the callback endpoint was accessed without
	// first going through the authorization endpoint. This indicates an invalid
	// or incomplete authorization flow, so the session must be deleted and an
	// error returned.
	if as.PolicyID == "" {
		as.Status = goidc.StatusFailure
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not delete the authentication session with a missing policy id: %w", err)
		}
		return fmt.Errorf("the authentication session is missing the policy id")
	}

	switch status, authErr := ctx.Policy(ctx.AuthPolicies, as.PolicyID).Authenticate(ctx.Response, ctx.Request, as, c); status {
	case goidc.StatusSuccess:
		as.Status = goidc.StatusSuccess
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the completed authentication session: %w", err)
		}

		grant, err := token.NewGrant(ctx, c, token.GrantOptions{
			Type: func() goidc.GrantType {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return goidc.GrantImplicit
				}
				return goidc.GrantAuthorizationCode
			}(),
			Subject:     as.Subject,
			Username:    as.Username,
			ClientID:    as.ClientID,
			Scopes:      as.GrantedScopes,
			Nonce:       as.Nonce,
			AuthDetails: as.GrantedAuthDetails,
			Resources:   as.GrantedResources,
			JWKThumbprint: func() string {
				if !ctx.DPoPEnabled {
					return ""
				}
				// Default to the JWK thumbprint stored in the session.
				// If not available, fallback to the thumbprint provided via the dpop_jkt parameter.
				if as.JWKThumbprint != "" {
					return as.JWKThumbprint
				}
				return as.DPoPJKT
			}(),
			AuthCode: func() string {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return ""
				}
				return ctx.AuthCode()
			}(),
			AuthCodeExpiresAt: func() int {
				if !as.ResponseType.Contains(goidc.ResponseTypeCode) {
					return 0
				}
				return timeutil.TimestampNow() + ctx.AuthCodeLifetimeSecs
			}(),
			AuthParams: as.AuthorizationParameters,
			Store:      as.Store,
		})
		if err != nil {
			return fmt.Errorf("could not generate the grant for the authentication session: %w", err)
		}

		redirectParams := response{
			authorizationCode: grant.AuthCode,
			state:             as.State,
		}
		if as.ResponseType.Contains(goidc.ResponseTypeToken) {
			tkn, tokenValue, err := token.Issue(ctx, grant, c, nil)
			if err != nil {
				return fmt.Errorf("could not generate the access token for the authentication session: %w", err)
			}
			redirectParams.accessToken = tokenValue
			redirectParams.tokenType = tkn.Type
		}

		if strutil.ContainsOpenID(as.GrantedScopes) && as.ResponseType.Contains(goidc.ResponseTypeIDToken) {
			idToken, err := token.MakeIDToken(ctx, c, token.IDTokenOptions{
				Subject:           as.Subject,
				Nonce:             as.Nonce,
				AccessToken:       redirectParams.accessToken,
				AuthorizationCode: grant.AuthCode,
				State:             as.State,
				Claims:            ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return fmt.Errorf("could not generate the id token for the authentication session: %w", err)
			}
			redirectParams.idToken = idToken
		}
		return redirectResponse(ctx, c, as.AuthorizationParameters, redirectParams)
	case goidc.StatusPending:
		as.Status = goidc.StatusPending
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the in-progress authentication session: %w", err)
		}
		return nil
	default:
		as.Status = goidc.StatusFailure
		if err := ctx.AuthSaveSession(as); err != nil {
			return fmt.Errorf("could not save the failed authentication session: %w", err)
		}

		var oidcErr goidc.Error
		if errors.As(authErr, &oidcErr) {
			return redirectionError{
				err:                     oidcErr,
				AuthorizationParameters: as.AuthorizationParameters,
			}
		}

		if authErr != nil {
			return wrapRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", as.AuthorizationParameters, authErr)
		}

		return newRedirectionError(goidc.ErrorCodeAccessDenied, "access denied", as.AuthorizationParameters)
	}
}
