// Package apple is the Apple Provider type: Sign in with Apple on the web
// by redirect with form_post and in Apps by client token, the code
// exchanged with a client secret JWT signed by the .p8 key, and the
// refresh token revoked on unlinking
// (docs/spec/architecture.md#apple-provider-类型).
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
)

const issuer = "https://appleid.apple.com"

// Endpoint is where Apple's /auth endpoints are; tests point it at a fake.
var Endpoint = issuer

func init() {
	provider.Register(provider.Type{
		Key:  "apple",
		Name: "Apple",
		Fields: []provider.ConfigField{
			// Apple's sub is per team: another team is another set of Users.
			{Field: channel.Field{Key: "team_id", Label: "Team ID", Type: "text"}, Immutable: true},
			{Field: channel.Field{Key: "key_id", Label: "Key ID", Type: "text"}},
			{Field: channel.Field{Key: "private_key", Label: "私钥(.p8)", Type: "text", Secret: true,
				Help: "粘贴 .p8 文件的全部内容"}},
			{Field: channel.Field{Key: "services_id", Label: "Services ID", Type: "text", Help: "Web 登录用"}},
			{Field: channel.Field{Key: "bundle_id", Label: "Bundle ID", Type: "text", Optional: true, Help: "iOS App 登录用"}},
		},
		New: func(c map[string]string) (provider.Redirect, error) {
			key, err := parseP8(c["private_key"])
			if err != nil {
				return nil, err
			}
			return &upstream{teamID: c["team_id"], keyID: c["key_id"], key: key, servicesID: c["services_id"], bundleID: c["bundle_id"]}, nil
		},
	})
}

// upstream is an Apple Provider. Web sign-in uses the Services ID as
// client_id; an App's code is exchanged with the Bundle ID (ADR 0011).
type upstream struct {
	teamID, keyID        string
	key                  *ecdsa.PrivateKey
	servicesID, bundleID string
}

// parseP8 reads a .p8 key, its line breaks lost or not.
func parseP8(s string) (*ecdsa.PrivateKey, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "-----BEGIN PRIVATE KEY-----")
	s = strings.TrimSuffix(s, "-----END PRIVATE KEY-----")
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("私钥不是 .p8 文件的内容")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if ec, ok := k.(*ecdsa.PrivateKey); err == nil && ok {
		return ec, nil
	}
	return nil, errors.New("私钥不是 .p8 文件的内容")
}

var client = &http.Client{Timeout: 10 * time.Second}

// AuthURL asks for no scope: Apple then sends neither name nor email.
// Apple has no PKCE; the client secret guards the code instead.
func (a *upstream) AuthURL(_ context.Context, redirectURI, state, nonce, _ string) (string, error) {
	return Endpoint + "/auth/authorize?" + url.Values{
		"response_type": {"code"},
		"response_mode": {"form_post"},
		"client_id":     {a.servicesID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"nonce":         {nonce},
	}.Encode(), nil
}

// Callback exchanges the code Apple posted back; the user field, Apple's
// name and email, is dropped.
func (a *upstream) Callback(ctx context.Context, params url.Values, redirectURI, nonce, _ string) (provider.Identity, error) {
	if e := params.Get("error"); e != "" {
		return provider.Identity{}, fmt.Errorf("apple: %s", e)
	}
	return a.exchange(ctx, a.servicesID, params.Get("code"), redirectURI, nonce)
}

// ClientToken exchanges the authorization_code Sign in with Apple gave an
// App, as its Bundle ID; Apple's own answer is the proof, so no identity
// token or nonce (ADR 0011).
func (a *upstream) ClientToken(ctx context.Context, code string) (provider.Identity, error) {
	if a.bundleID == "" {
		return provider.Identity{}, errors.New("apple: no Bundle ID set")
	}
	return a.exchange(ctx, a.bundleID, code, "", "")
}

// exchange trades code for tokens as clientID, and returns who signed in
// with the refresh token to revoke later. An empty nonce is not checked.
func (a *upstream) exchange(ctx context.Context, clientID, code, redirectURI, nonce string) (provider.Identity, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := a.post(ctx, "/auth/token", clientID, form, &tok); err != nil {
		return provider.Identity{}, err
	}
	// The id_token came straight from Apple over TLS, which stands in for
	// its signature (OIDC Core §3.1.3.7 6).
	parsed, err := jwt.ParseSigned(tok.IDToken, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return provider.Identity{}, fmt.Errorf("apple id_token: %w", err)
	}
	var claims jwt.Claims
	var extra struct {
		Nonce string `json:"nonce"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims, &extra); err != nil {
		return provider.Identity{}, fmt.Errorf("apple id_token: %w", err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{clientID}}, time.Minute); err != nil {
		return provider.Identity{}, fmt.Errorf("apple id_token: %w", err)
	}
	switch {
	case claims.Expiry == nil:
		return provider.Identity{}, errors.New("apple id_token: no exp")
	case claims.Subject == "":
		return provider.Identity{}, errors.New("apple id_token: no sub")
	case nonce != "" && extra.Nonce != nonce:
		return provider.Identity{}, errors.New("apple id_token: wrong nonce")
	case tok.RefreshToken == "":
		return provider.Identity{}, errors.New("apple: no refresh token")
	}
	// The token keeps the client_id it was issued to, which revoking needs.
	return provider.Identity{Subject: claims.Subject, Token: clientID + " " + tok.RefreshToken}, nil
}

// Unlink revokes the refresh token, which ends the User's authorization
// of this App at Apple.
func (a *upstream) Unlink(ctx context.Context, token string) error {
	clientID, refresh, ok := strings.Cut(token, " ")
	if !ok {
		return errors.New("apple: malformed stored token")
	}
	return a.post(ctx, "/auth/revoke", clientID, url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}, nil)
}

// post sends form to Apple's endpoint path as clientID, and decodes a 200
// JSON answer into out.
func (a *upstream) post(ctx context.Context, path, clientID string, form url.Values, out any) error {
	secret, err := a.clientSecret(clientID)
	if err != nil {
		return err
	}
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("apple %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple %s: %s: %.200s", path, resp.Status, body)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// clientSecret signs a fresh, short-lived client secret for clientID.
func (a *upstream) clientSecret(clientID string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), a.keyID))
	if err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: a.teamID, Subject: clientID, Audience: jwt.Audience{issuer},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).Serialize()
}
