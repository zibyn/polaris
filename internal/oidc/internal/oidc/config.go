package oidc

import (
	"context"

	"github.com/zibyn/polaris/internal/oidc/goidc"
)

type Configuration struct {
	GrantManager goidc.GrantManager
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string

	AuthManager          goidc.AuthManager
	AuthTimeoutSecs      int
	AuthCodeFunc         goidc.RandomFunc
	AuthCodeLifetimeSecs int
	AuthSessionIDFunc    goidc.RandomFunc

	OpaqueTokenEnabled bool
	OpaqueTokenManager goidc.OpaqueTokenManager

	// JWKSFunc retrieves the server's JWKS.
	// The returned JWKS must include private keys if SignerFunc is not provided.
	// When exposing it at the jwks endpoint, any private information is removed.
	JWKSFunc   goidc.JWKSFunc
	SignerFunc goidc.SignerFunc

	HandleGrantFunc    goidc.HandleGrantFunc
	HandleTokenFunc    goidc.HandleTokenFunc
	IDTokenClaimsFunc  goidc.IDTokenClaimsFunc
	UserInfoClaimsFunc goidc.UserInfoClaimsFunc
	TokenClaimsFunc    goidc.TokenClaimsFunc
	AuthPolicies       []goidc.AuthnPolicy
	Scopes             []goidc.Scope
	OpenIDRequired     bool
	GrantTypes         []goidc.GrantType
	ResponseTypes      []goidc.ResponseType
	ResponseModes      []goidc.ResponseMode
	GrantIDFunc        goidc.RandomFunc
	ACRs               []goidc.ACR
	DisplayValues      []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims                   []string
	ClaimTypes               []goidc.ClaimType
	SubIdentifierTypeDefault goidc.SubIdentifierType
	SubIdentifierTypes       []goidc.SubIdentifierType
	PairwiseSubjectFunc      goidc.PairwiseSubjectFunc
	ClientManager            goidc.ClientManager
	StaticClients            []*goidc.Client
	// IssuerRespParamEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamEnabled bool
	// ClaimsParamEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamEnabled bool
	RenderErrorFunc    goidc.RenderErrorFunc
	HandleErrorFunc    goidc.HandleErrorFunc

	AuthnMethods                            []goidc.AuthnMethod
	AuthnMethodDefault                      goidc.AuthnMethod
	AuthnMethodPrivateKeyJWTSigAlgs         []goidc.SignatureAlgorithm
	AuthnMethodSecretJWTSigAlgs             []goidc.SignatureAlgorithm
	AuthnMethodAttestationJWTIssuers        []goidc.AttestationIssuer
	AuthnMethodAttestationJWTHTTPClientFunc goidc.HTTPClientFunc

	TokenEndpoint          string
	OpaqueTokenFunc        goidc.OpaqueTokenFunc
	TokenOptionsFunc       goidc.TokenOptionsFunc
	VerifyClientSecretFunc goidc.VerifyClientSecretFunc
	// TokenBindingRequired indicates that at least one mechanism of sender
	// contraining tokens is required (DPoP).
	TokenBindingRequired bool

	JWKSEndpoint          string
	AuthorizationEndpoint string
	EndpointPrefix        string

	UserInfoEndpoint       string
	UserInfoDefaultSigAlg  goidc.SignatureAlgorithm
	UserInfoSigAlgs        []goidc.SignatureAlgorithm
	UserInfoEncEnabled     bool
	UserInfoKeyEncAlgs     []goidc.KeyEncryptionAlgorithm
	UserInfoContentEncAlgs []goidc.ContentEncryptionAlgorithm

	IDTokenDefaultSigAlg  goidc.SignatureAlgorithm
	IDTokenSigAlgs        []goidc.SignatureAlgorithm
	IDTokenEncEnabled     bool
	IDTokenKeyEncAlgs     []goidc.KeyEncryptionAlgorithm
	IDTokenContentEncAlgs []goidc.ContentEncryptionAlgorithm
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	JWTLifetimeSecs   int
	JWTLeewayTimeSecs int
	JWTIDFunc         goidc.RandomFunc

	LocalhostRedirectURIEnabled bool

	TokenIntrospectionEnabled             bool
	TokenIntrospectionEndpoint            string
	TokenIntrospectionIsClientAllowedFunc goidc.IsClientAllowedTokenIntrospectionFunc

	TokenRevocationEnabled                         bool
	TokenRevocationEndpoint                        string
	TokenRevocationIsClientAllowedFunc             goidc.IsClientAllowedFunc
	TokenRevocationRevokeGrantOnAccessTokenEnabled bool

	RefreshTokenManager         goidc.RefreshTokenManager
	RefreshTokenFunc            goidc.RandomFunc
	RefreshTokenShouldIssueFunc goidc.RefreshTokenShouldIssueFunc
	RefreshTokenRotationEnabled bool
	RefreshTokenLifetimeSecs    int

	DPoPEnabled  bool
	DPoPRequired bool
	DPoPSigAlgs  []goidc.SignatureAlgorithm

	PKCEEnabled                bool
	PKCERequired               bool
	PKCEDefaultChallengeMethod goidc.CodeChallengeMethod
	PKCEChallengeMethods       []goidc.CodeChallengeMethod

	RAREnabled            bool
	RARDetailTypes        []goidc.AuthDetailType
	RARValidateDetailFunc func(context.Context, goidc.AuthDetail) error
	RARCompareDetailsFunc goidc.RARCompareDetailsFunc

	ResourceIndicatorsEnabled bool
	// ResourceIndicatorsRequired indicates that the resource parameter is
	// required during authorization requests.
	ResourceIndicatorsRequired bool
	ResourceIndicators         []goidc.ResourceIndicator

	HTTPClientFunc goidc.HTTPClientFunc
	ConsumeJTIFunc goidc.ConsumeJTIFunc

	ErrorURI string

	// AuthorizationChallengeEndpoint, if set, is published in discovery; the
	// endpoint itself is served outside the provider, which only lends it
	// client authentication and code issuance.
	AuthorizationChallengeEndpoint string

	LogoutEnabled               bool
	BackChannelLogoutEnabled    bool
	LogoutEndpoint              string
	LogoutManager               goidc.LogoutManager
	LogoutSessionTimeoutSecs    int
	LogoutPolicies              []goidc.LogoutPolicy
	LogoutSessionIDFunc         goidc.RandomFunc
	HandleDefaultPostLogoutFunc goidc.HandleDefaultPostLogoutFunc
}
