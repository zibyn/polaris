package token

import (
	"errors"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/dpop"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
)

// ValidatePoP validates that the context contains the information required to
// prove the client's possession of the token.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func ValidatePoP(ctx oidc.Context, token string, cnf goidc.TokenConfirmation) error {
	return validateDPoP(ctx, token, cnf)
}

// validateDPoP validates that the context contains the information required to
// prove the client's possession of the access token with DPoP if applicable.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func validateDPoP(ctx oidc.Context, token string, confirmation goidc.TokenConfirmation) error {
	if confirmation.JWKThumbprint == "" {
		return nil
	}
	if !ctx.DPoPEnabled {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the token is bound to DPoP, but DPoP support is disabled"))
	}

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("a DPoP proof is required for this token"))
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		AccessToken:   token,
		JWKThumbprint: confirmation.JWKThumbprint,
	})
}

// dpopThumbprint returns the DPoP JWK thumbprint from the request context,
// or an empty string if DPoP is not enabled or no DPoP JWT is present.
func dpopThumbprint(ctx oidc.Context) string {
	if !ctx.DPoPEnabled {
		return ""
	}
	if dpopJWT, ok := dpop.JWT(ctx); ok {
		return dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}
	return ""
}
