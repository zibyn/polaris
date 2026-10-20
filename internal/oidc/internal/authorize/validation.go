package authorize

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/strutil"
	"github.com/zibyn/polaris/internal/oidc/internal/token"
)

// validateRequest validates the parameters sent in an authorization request.
func validateRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	return validateParams(ctx, req.AuthorizationParameters, c)
}

// -------------------------------------------------- Helper Functions -------------------------------------------------- //

// validateParams validates the parameters of an authorization request.
func validateParams(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.RedirectURI == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("redirect_uri is required"))
	}

	if err := validateParamsAsOptionals(ctx, params, c); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("response_type is required"))
	}

	if ctx.ResourceIndicatorsRequired && params.Resources == nil {
		return wrapRedirectionError(goidc.ErrorCodeInvalidTarget, "invalid target", params,
			errors.New("the resource parameter is required"))
	}

	if ctx.OpenIDRequired && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "scope openid is required", params,
			errors.New("scope openid is required"))
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("id_token requires the openid scope"))
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("nonce is required when response_type includes id_token"))
	}

	if err := validatePKCE(ctx, params, c); err != nil {
		return err
	}

	return nil
}

// validateParamsAsOptionals validates the parameters of an authorization
// request considering them as optional.
// This validation is meant to be shared by all authorization requests.
// The redirect URI is ALWAYS validated before any other validations, since
// it determines when or not to redirect errors.
func validateParamsAsOptionals(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if err := validateRedirectURIAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateRequestObjectAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateScopesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResponseTypeAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResponseModeAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateCodeChallengeMethodAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateAuthDetailsAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateACRValuesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResourcesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateIDTokenHintAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateDisplayValueAsOptional(ctx, params, c); err != nil {
		return err
	}

	return nil
}

func validateRedirectURIAsOptional(_ oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.RedirectURI == "" {
		return nil
	}

	parsedURI, err := url.Parse(params.RedirectURI)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri", err)
	}

	// RFC 8252: Native apps can use loopback interface redirect URIs on any port.
	// Port wildcards must not apply to non-loopback redirect URIs.
	if host, ip := parsedURI.Hostname(), net.ParseIP(parsedURI.Hostname()); c.ApplicationType == goidc.ApplicationTypeNative && ip != nil && ip.IsLoopback() {
		if host == "::1" {
			host = "[::1]"
		}
		parsedURI.Host = host
	}

	if !slices.Contains(c.RedirectURIs, parsedURI.String()) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri", errors.New("redirect_uri is not registered for the client"))
	}

	return nil
}

// validateRequestObjectAsOptional rejects request objects: JAR is not
// supported, so neither request nor request_uri may be used.
func validateRequestObjectAsOptional(_ oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.RequestObject != "" {
		return newRedirectionError(goidc.ErrorCodeRequestNotSupported, "request is not supported", params)
	}
	if params.RequestURI != "" {
		return newRedirectionError(goidc.ErrorCodeRequestURINotSupported, "request_uri is not supported", params)
	}
	return nil
}

func validateCodeChallengeMethodAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.CodeChallengeMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.PKCEChallengeMethods, params.CodeChallengeMethod) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("code_challenge_method is not supported"))
	}

	return nil
}

func validateDisplayValueAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.Display == "" {
		return nil
	}

	if !slices.Contains(ctx.DisplayValues, params.Display) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("display is not supported"))
	}

	return nil
}

func validateScopesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.Scopes == "" {
		return nil
	}

	for s := range strings.FieldsSeq(params.Scopes) {
		scope, ok := ctx.Scope(s)
		if !ok {
			return wrapRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params, fmt.Errorf("scope %s does not match any available scope", s))
		}

		if !slices.Contains(strings.Fields(c.ScopeIDs), scope.ID) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params, fmt.Errorf("scope %s is not allowed for the client", s))
		}
	}

	if ctx.OpenIDRequired && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "scope openid is required", params,
			errors.New("scope openid is required"))
	}

	return nil
}

func validatePKCE(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if ctx.PKCEEnabled && c.IsPublic() && params.CodeChallenge == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("pkce is required for public clients"))
	}

	if ctx.PKCERequired && params.CodeChallenge == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("code_challenge is required"))
	}
	return nil
}

func validateResponseTypeAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.ResponseType == "" {
		return nil
	}

	if !slices.Contains(ctx.ResponseTypes, params.ResponseType) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params)
	}

	if !slices.Contains(c.ResponseTypes, params.ResponseType) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) && !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidGrant, "invalid grant", params,
			errors.New("response_type includes code but the client is not allowed to use the authorization_code grant"))
	}

	if params.ResponseType.IsImplicit() && !slices.Contains(c.GrantTypes, goidc.GrantImplicit) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params,
			errors.New("the implicit response types are not allowed for the client"))
	}

	return nil
}

func validateResponseModeAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.ResponseMode == "" {
		return nil
	}

	if !slices.Contains(ctx.ResponseModes, params.ResponseMode) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params)
	}

	if params.ResponseMode.IsQuery() && params.ResponseType.IsImplicit() {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params,
			errors.New("response_mode query is not allowed with implicit or hybrid response types"))
	}

	return nil
}

func validateAuthDetailsAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if !ctx.RAREnabled || params.AuthDetails == nil {
		return nil
	}

	for _, detail := range params.AuthDetails {
		typ := detail.Type()
		if typ == "" {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				errors.New("authorization detail type is required"))
		}

		if !slices.Contains(ctx.RARDetailTypes, typ) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				fmt.Errorf("authorization detail type %q is not supported", typ))
		}

		if c.AuthDetailTypes != nil && !slices.Contains(c.AuthDetailTypes, typ) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				fmt.Errorf("authorization detail type %q is not allowed for the client", typ))
		}

		if err := ctx.RARValidateDetail(detail); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params, err)
		}
	}

	return nil
}

func validateACRValuesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.ACRValues == "" {
		return nil
	}

	for acr := range strings.FieldsSeq(params.ACRValues) {
		if !slices.Contains(ctx.ACRs, goidc.ACR(acr)) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
				fmt.Errorf("acr value %q is not supported", acr))
		}
	}

	return nil
}

func validateResourcesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if !ctx.ResourceIndicatorsEnabled || params.Resources == nil {
		return nil
	}

	for _, resource := range params.Resources {
		if !slices.Contains(ctx.ResourceIndicators, resource) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidTarget, "invalid target", params,
				fmt.Errorf("resource %q is not configured by the server", resource))
		}
	}

	return nil
}

func validateIDTokenHintAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.IDTokenHint == "" {
		return nil
	}

	idTkn, err := token.IDToken(ctx, params.IDTokenHint)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint", err)
	}

	if !slices.Contains([]string(idTkn.Audience), c.ID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint",
			errors.New("the id_token_hint audience does not match the client"))
	}

	return nil
}
