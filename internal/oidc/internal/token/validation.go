package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/dpop"
	"github.com/zibyn/polaris/internal/oidc/internal/hashutil"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
)

// ValidateBinding checks DPoP binding for issuing a token.
func ValidateBinding(ctx oidc.Context, c *goidc.Client, opts *bindindValidationOptions) error {
	if opts == nil {
		opts = &bindindValidationOptions{}
	}
	if err := validateBindingDPoP(ctx, c, *opts); err != nil {
		return err
	}

	return validateBindingRequirement(ctx)
}

func validateBindingDPoP(ctx oidc.Context, c *goidc.Client, opts bindindValidationOptions) error {
	if !ctx.DPoPEnabled {
		if opts.dpopRequired || opts.dpopJWKThumbprint != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
				errors.New("the request requires DPoP token binding, but DPoP support is disabled"))
		}
		return nil
	}

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// Return an error if the DPoP header was not informed and one of the
		// below applies:
		// 	* DPoP is required as a general configuration.
		// 	* The client requires DPoP.
		// 	* DPoP is required as a validation option.
		if ctx.DPoPRequired || c.DPoPTokenBindingRequired || opts.dpopRequired {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("a DPoP proof is required for this token request"))
		}
		return nil
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		JWKThumbprint: opts.dpopJWKThumbprint,
	})
}

func validateBindingRequirement(ctx oidc.Context) error {
	if !ctx.TokenBindingRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := dpop.JWT(ctx)
	if ctx.DPoPEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("token binding with dpop is required"))
	}

	return nil
}

type resourceValidationOptions struct {
	granted goidc.Resources
}

func validateResources(ctx oidc.Context, req request, opts *resourceValidationOptions) error {
	if !ctx.ResourceIndicatorsEnabled {
		return nil
	}

	for _, r := range req.resources {
		if !slices.Contains(ctx.ResourceIndicators, r) {
			return goidc.WrapError(goidc.ErrorCodeInvalidTarget, "invalid target", fmt.Errorf("resource %q is not configured by the server", r))
		}

		if opts != nil && !slices.Contains(opts.granted, r) {
			return goidc.WrapError(goidc.ErrorCodeInvalidTarget, "invalid target", fmt.Errorf("resource %q was not granted for this authorization", r))
		}
	}

	return nil
}

type authDetailsValidationOptions struct {
	granted []goidc.AuthDetail
}

// validateAuthDetails validates the auth details for the token request.
func validateAuthDetails(ctx oidc.Context, req request, c *goidc.Client, opts *authDetailsValidationOptions) error {
	if !ctx.RAREnabled || req.authDetails == nil {
		return nil
	}

	for _, detail := range req.authDetails {
		if !slices.Contains(ctx.RARDetailTypes, detail.Type()) {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", fmt.Errorf("authorization detail type %q is not supported", detail.Type()))
		}

		if c.AuthDetailTypes != nil && !slices.Contains(c.AuthDetailTypes, detail.Type()) {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", fmt.Errorf("authorization detail type %q is not allowed for the client", detail.Type()))
		}

		if err := ctx.RARValidateDetail(detail); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", err)
		}
	}

	if opts != nil {
		if err := ctx.RARCompareAuthDetails(req.authDetails, opts.granted); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", err)
		}
	}

	return nil
}

type scopeValidationOptions struct {
	granted string
}

func validateScopes(ctx oidc.Context, req request, c *goidc.Client, opts *scopeValidationOptions) error {
	if req.scopes == "" {
		return nil
	}

	for s := range strings.FieldsSeq(req.scopes) {
		scope, ok := ctx.Scope(s)
		if !ok {
			return goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope", fmt.Errorf("scope %s does not match any available scope", s))
		}

		if !slices.Contains(strings.Fields(c.ScopeIDs), scope.ID) {
			return goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope", fmt.Errorf("scope %s is not allowed for the client", s))
		}

		if opts != nil && !slices.Contains(strings.Fields(opts.granted), s) {
			return goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope", fmt.Errorf("scope %s is not granted", s))
		}
	}

	return nil
}

func validatePKCE(ctx oidc.Context, req request, grant *goidc.Grant) error {
	if !ctx.PKCEEnabled {
		return nil
	}

	if grant.AuthParams.CodeChallenge == "" {
		// [RFC 9700] a token request containing a code_verifier parameter is
		// accepted only if a code_challenge parameter was present in the authorization request.
		if req.codeVerifier != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier",
				errors.New("code_verifier was informed in the request, but no code_challenge was provided previously"))
		}
		return nil
	}

	// [RFC 7636] with a minimum length of 43 characters and a maximum length of 128 characters.
	if verifierLengh := len(req.codeVerifier); verifierLengh < 43 || verifierLengh > 128 {
		return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier", fmt.Errorf("code_verifier length %d is outside the allowed range", verifierLengh))
	}

	method := ctx.PKCEDefaultChallengeMethod
	if grant.AuthParams.CodeChallengeMethod != "" && slices.Contains(ctx.PKCEChallengeMethods, grant.AuthParams.CodeChallengeMethod) {
		method = grant.AuthParams.CodeChallengeMethod
	}

	switch verifier, challenge := req.codeVerifier, grant.AuthParams.CodeChallenge; method {
	case goidc.CodeChallengeMethodPlain:
		if verifier != challenge {
			return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier", errors.New("the code_verifier does not match the plain code_challenge"))
		}
	case goidc.CodeChallengeMethodSHA256:
		if hashutil.Thumbprint(verifier) != challenge {
			return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier", errors.New("the code_verifier does not match the SHA-256 code_challenge"))
		}
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier", fmt.Errorf("pkce method %s is not supported", method))
	}

	return nil
}
