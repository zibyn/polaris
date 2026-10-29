package discovery

import (
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
)

func NewConfiguration(ctx oidc.Context) goidc.Configuration {
	scopes := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopes[i] = scope.ID
	}

	config := goidc.Configuration{
		Issuer:                     ctx.Issuer(),
		AuthorizationEndpoint:      ctx.BaseURL() + ctx.AuthorizationEndpoint,
		UserInfoEndpoint:           ctx.BaseURL() + ctx.UserInfoEndpoint,
		TokenEndpoint:              ctx.BaseURL() + ctx.TokenEndpoint,
		JWKSEndpoint:               ctx.BaseURL() + ctx.JWKSEndpoint,
		ResponseTypes:              ctx.ResponseTypes,
		ResponseModes:              ctx.ResponseModes,
		GrantTypes:                 ctx.GrantTypes,
		UserClaimsSupported:        ctx.Claims,
		ClaimTypesSupported:        ctx.ClaimTypes,
		SubIdentifierTypes:         ctx.SubIdentifierTypes,
		IDTokenSigAlgs:             ctx.IDTokenSigAlgs,
		UserInfoSigAlgs:            ctx.UserInfoSigAlgs,
		Scopes:                     scopes,
		TokenAuthnMethods:          ctx.AuthnMethods,
		TokenAuthnSigAlgs:          ctx.TokenAuthnSigAlgs(),
		IssuerResponseParamEnabled: ctx.IssuerRespParamEnabled,
		ClaimsParamEnabled:         ctx.ClaimsParamEnabled,
		AuthDetailsEnabled:         ctx.RAREnabled,
		AuthDetailTypesSupported:   ctx.RARDetailTypes,
		ACRs:                       ctx.ACRs,
		DisplayValues:              ctx.DisplayValues,
	}

	if ctx.DPoPEnabled {
		config.DPoPSigAlgs = ctx.DPoPSigAlgs
	}

	if ctx.TokenIntrospectionEnabled {
		config.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.TokenIntrospectionEndpoint
		config.TokenIntrospectionAuthnMethods = ctx.AuthnMethods
		config.TokenIntrospectionAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.TokenRevocationEnabled {
		config.TokenRevocationEndpoint = ctx.BaseURL() + ctx.TokenRevocationEndpoint
		config.TokenRevocationAuthnMethods = ctx.AuthnMethods
		config.TokenRevocationAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.UserInfoEncEnabled {
		config.UserInfoKeyEncAlgs = ctx.UserInfoKeyEncAlgs
		config.UserInfoContentEncAlgs = ctx.UserInfoContentEncAlgs
	}

	if ctx.IDTokenEncEnabled {
		config.IDTokenKeyEncAlgs = ctx.IDTokenKeyEncAlgs
		config.IDTokenContentEncAlgs = ctx.IDTokenContentEncAlgs
	}

	if ctx.PKCEEnabled {
		config.CodeChallengeMethods = ctx.PKCEChallengeMethods
	}

	if ctx.LogoutEnabled {
		config.EndSessionEndpoint = ctx.BaseURL() + ctx.LogoutEndpoint
	}

	if ctx.BackChannelLogoutEnabled {
		config.BackChannelLogoutSupported = true
		config.BackChannelLogoutSessionSupported = true
	}

	if ctx.AuthorizationChallengeEndpoint != "" {
		config.AuthorizationChallengeEndpoint = ctx.BaseURL() + ctx.AuthorizationChallengeEndpoint
	}

	return config
}
