// Package oidc is the generic OIDC Provider type: any upstream with
// discovery, signed in to by authorization code + PKCE, its id_token checked
// against the issuer's JWKS (docs/spec/architecture.md#通用-oidc-provider-类型).
// The named providers (Google, Microsoft) are built on the same
// implementation through Type, not by copying it.
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
)

func init() {
	provider.Register(Type(Options{
		Key:  "oidc",
		Name: "通用 OIDC",
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "issuer", Label: "Issuer", Type: "url",
				Help: "须提供 /.well-known/openid-configuration"}, Immutable: true},
			{Field: channel.Field{Key: "client_id", Label: "Client ID", Type: "text"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client secret", Type: "text", Secret: true}},
		},
		Issuer: func(c map[string]string) (string, error) { return c["issuer"], nil },
	}))
}

// Options describe a Provider type that signs in with the generic OIDC
// flow: what the admin is asked for, and which issuer is acceptable.
type Options struct {
	Key, Name string
	Fields    []provider.ConfigField
	// Issuer is what the type is configured for, built from settings that
	// passed the Fields checks: a constant for a named provider, the
	// admin's own issuer for the generic one.
	Issuer func(config map[string]string) (string, error)
	// IssuerMatches replaces the exact comparison with the configured
	// issuer, for a type whose upstream reports something else: Microsoft
	// names the tenant it signed (ADR 0013). claims are the id_token's,
	// nil wherever there is no id_token to anchor against — in discovery
	// and for the callback's iss parameter.
	IssuerMatches func(configured, reported string, claims map[string]any) bool
}

// Type builds the Provider type the Options describe.
func Type(o Options) provider.Type {
	return provider.Type{
		Key: o.Key, Name: o.Name, Fields: o.Fields,
		New: func(c map[string]string) (provider.Redirect, error) {
			issuer, err := o.Issuer(c)
			if err != nil {
				return nil, err
			}
			u := &upstream{issuer: strings.TrimSuffix(issuer, "/"), clientID: c["client_id"], secret: c["client_secret"]}
			u.matches = o.IssuerMatches
			if u.matches == nil {
				u.matches = sameIssuer
			}
			return u, nil
		},
	}
}

// sameIssuer is the default: the upstream reports exactly what it was
// configured with.
func sameIssuer(configured, reported string, _ map[string]any) bool { return configured == reported }

type upstream struct {
	issuer, clientID, secret string
	matches                  func(configured, reported string, claims map[string]any) bool
}

var client = &http.Client{Timeout: 10 * time.Second}

func (u *upstream) AuthURL(ctx context.Context, redirectURI, state, nonce, verifier string) (string, error) {
	d, err := u.discovery(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {u.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return d.AuthorizationEndpoint + sep + q.Encode(), nil
}

func (u *upstream) Callback(ctx context.Context, params url.Values, redirectURI, nonce, verifier string) (provider.Identity, error) {
	if e := params.Get("error"); e != "" {
		return provider.Identity{}, fmt.Errorf("upstream: %s %s", e, params.Get("error_description"))
	}
	if iss := params.Get("iss"); iss != "" && !u.matches(u.issuer, iss, nil) { // RFC 9207
		return provider.Identity{}, fmt.Errorf("callback from issuer %q", iss)
	}
	d, err := u.discovery(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {params.Get("code")},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	// client_secret_basic is the default; post only for an upstream without it.
	post := len(d.TokenAuthMethods) > 0 && !slices.Contains(d.TokenAuthMethods, "client_secret_basic")
	if post {
		form.Set("client_id", u.clientID)
		form.Set("client_secret", u.secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return provider.Identity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if !post {
		req.SetBasicAuth(url.QueryEscape(u.clientID), url.QueryEscape(u.secret)) // RFC 6749 §2.3.1
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := fetch(req, &tok); err != nil {
		return provider.Identity{}, fmt.Errorf("token endpoint: %w", err)
	}
	return u.verify(ctx, d, tok.IDToken, nonce)
}

// verify checks an id_token from the token endpoint (OIDC Core §3.1.3.7)
// and says who signed in, and when if it says.
func (u *upstream) verify(ctx context.Context, d *discovery, idToken, nonce string) (provider.Identity, error) {
	var id provider.Identity
	algs := []jose.SignatureAlgorithm{}
	for _, a := range d.SigningAlgs {
		if a != "none" && !strings.HasPrefix(a, "HS") { // never the alg the token picks for itself
			algs = append(algs, jose.SignatureAlgorithm(a))
		}
	}
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.RS256}
	}
	tok, err := jwt.ParseSigned(idToken, algs)
	if err != nil {
		return id, fmt.Errorf("id_token: %w", err)
	}
	if len(tok.Headers) != 1 {
		return id, errors.New("id_token: one signature expected")
	}
	key, err := d.key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return id, err
	}
	var claims jwt.Claims
	var extra struct {
		Nonce    string           `json:"nonce"`
		AZP      string           `json:"azp"`
		AuthTime *jwt.NumericDate `json:"auth_time"`
		Tid      string           `json:"tid"`
	}
	if err := tok.Claims(key, &claims, &extra); err != nil {
		return id, fmt.Errorf("id_token: %w", err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{u.clientID}}, time.Minute); err != nil {
		return id, fmt.Errorf("id_token: %w", err)
	}
	if !u.matches(u.issuer, claims.Issuer, map[string]any{"tid": extra.Tid}) {
		return id, fmt.Errorf("id_token: issuer %q is not ours", claims.Issuer)
	}
	if claims.Expiry == nil {
		return id, errors.New("id_token: no exp")
	}
	if len(claims.Audience) > 1 && extra.AZP != u.clientID {
		return id, errors.New("id_token: azp is not us")
	}
	if extra.Nonce != nonce {
		return id, errors.New("id_token: wrong nonce")
	}
	if claims.Subject == "" {
		return id, errors.New("id_token: no sub")
	}
	id.Subject = claims.Subject
	if extra.AuthTime != nil {
		id.AuthTime = extra.AuthTime.Time()
	}
	return id, nil
}

// discovery is an issuer's /.well-known/openid-configuration, with its
// JWKS once fetched.
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`

	fetched time.Time
	mu      sync.Mutex
	jwks    jose.JSONWebKeySet
	jwksAt  time.Time
}

// discovery is the issuer's discovery document, once this Provider has
// checked it is the one it accepts.
func (u *upstream) discovery(ctx context.Context) (*discovery, error) {
	d, err := discover(ctx, u.issuer)
	if err != nil {
		return nil, err
	}
	if !u.matches(u.issuer, d.Issuer, nil) {
		return nil, fmt.Errorf("discovery of %s: issuer %q", u.issuer, d.Issuer)
	}
	return d, nil
}

// cacheFor is how long a discovery document and JWKS are reused.
const cacheFor = time.Hour

// cache holds each issuer's discovery, in this process only.
var cache sync.Map // issuer → *discovery

func discover(ctx context.Context, issuer string) (*discovery, error) {
	if v, ok := cache.Load(issuer); ok && time.Since(v.(*discovery).fetched) < cacheFor {
		return v.(*discovery), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	d := &discovery{}
	if err := fetch(req, d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery of %s: endpoints missing", issuer)
	}
	d.fetched = time.Now()
	cache.Store(issuer, d)
	return d, nil
}

// key returns the signing key kid names, fetching the JWKS again when it is
// not there: the upstream rotated keys.
// ponytail: an unknown kid refetches at most once a minute; enough for one
// upstream's rotations, not a defence against a flood of forged kids.
func (d *discovery) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	find := func() *jose.JSONWebKey {
		for _, k := range d.jwks.Keys {
			if (kid == "" || k.KeyID == kid) && k.Use != "enc" {
				return &k
			}
		}
		return nil
	}
	if k := find(); k != nil && time.Since(d.jwksAt) < cacheFor {
		return k, nil
	}
	if time.Since(d.jwksAt) > time.Minute {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
		if err != nil {
			return nil, err
		}
		var set jose.JSONWebKeySet
		if err := fetch(req, &set); err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		d.jwks, d.jwksAt = set, time.Now()
	}
	if k := find(); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("id_token: no key %q in the issuer's JWKS", kid)
}

func fetch(req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %.200s", resp.Status, body)
	}
	return json.Unmarshal(body, out)
}
