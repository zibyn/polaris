package token

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
)

type GrantOptions struct {
	Type              goidc.GrantType
	Subject           string
	Username          string
	ClientID          string
	Scopes            string
	AuthDetails       []goidc.AuthDetail
	Resources         goidc.Resources
	Nonce             string
	AuthCode          string
	AuthCodeExpiresAt int
	JWKThumbprint     string
	AuthParams        goidc.AuthorizationParameters
	Store             map[string]any
}

func NewGrant(ctx oidc.Context, c *goidc.Client, opts GrantOptions) (*goidc.Grant, error) {
	grant := &goidc.Grant{
		ID:                ctx.GrantID(),
		AuthCode:          opts.AuthCode,
		AuthCodeExpiresAt: opts.AuthCodeExpiresAt,
		Subject:           opts.Subject,
		Username:          opts.Username,
		ClientID:          opts.ClientID,
		Scopes:            opts.Scopes,
		Store:             opts.Store,
		JWKThumbprint:     opts.JWKThumbprint,
		AuthParams:        opts.AuthParams,
		CreatedAt:         timeutil.TimestampNow(),
	}
	if ctx.RAREnabled {
		grant.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsEnabled {
		grant.Resources = opts.Resources
	}
	if err := ctx.HandleGrant(opts.Type, grant); err != nil {
		return nil, err
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) && slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) &&
		ctx.RefreshTokenShouldIssue(c, grant) && opts.Subject != c.ID {
		grant.RefreshToken = ctx.RefreshToken()
		if ctx.RefreshTokenLifetimeSecs != 0 {
			grant.RefreshTokenExpiresAt = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
		}
	}

	if err := ctx.SaveGrant(grant); err != nil {
		return nil, err
	}

	return grant, nil
}

type IDTokenOptions struct {
	Subject string
	Nonce   string
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
	RefreshToken      string
	Claims            map[string]any
}

type request struct {
	grantType    goidc.GrantType
	scopes       string
	code         string
	redirectURI  string
	refreshToken string
	codeVerifier string
	resources    goidc.Resources
	authDetails  []goidc.AuthDetail
}

func newRequest(r *http.Request) request {
	req := request{
		grantType:    goidc.GrantType(r.PostFormValue("grant_type")),
		scopes:       r.PostFormValue("scope"),
		code:         r.PostFormValue("code"),
		redirectURI:  r.PostFormValue("redirect_uri"),
		refreshToken: r.PostFormValue("refresh_token"),
		codeVerifier: r.PostFormValue("code_verifier"),
		resources:    r.PostForm["resource"],
	}

	if authDetails := r.PostFormValue("authorization_details"); authDetails != "" {
		var authDetailsObject []goidc.AuthDetail
		if err := json.Unmarshal([]byte(authDetails), &authDetailsObject); err == nil {
			req.authDetails = authDetailsObject
		}
	}

	return req
}

type response struct {
	AccessToken          string             `json:"access_token,omitempty"`
	IDToken              string             `json:"id_token,omitempty"`
	RefreshToken         string             `json:"refresh_token,omitempty"`
	ExpiresIn            int                `json:"expires_in,omitempty"`
	TokenType            goidc.TokenType    `json:"token_type,omitempty"`
	Scopes               string             `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthDetail `json:"authorization_details,omitempty"`
	Resources            goidc.Resources    `json:"resources,omitempty"`
}

type queryRequest struct {
	token         string
	tokenTypeHint goidc.TokenTypeHint
}

func newQueryRequest(req *http.Request) queryRequest {
	return queryRequest{
		token:         req.PostFormValue("token"),
		tokenTypeHint: goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

type bindindValidationOptions struct {
	dpopRequired      bool
	dpopJWKThumbprint string
}
