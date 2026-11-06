// Package polaris checks Polaris tokens in Go API backends: access tokens
// (RFC 9068) with a net/http middleware, and Back-Channel Logout tokens.
// Signing keys come from the issuer's JWKS, fetched again when a token is
// signed with a key not seen yet (key rotation). See ADR 0035.
package polaris

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// Claims of a valid access token.
type Claims struct {
	Sub      string `json:"sub"`
	ClientID string `json:"client_id"`
	// The Entitlements held at this API; empty when none, as for most M2M tokens.
	Entitlements []string `json:"entitlements"`
}

// LogoutToken is a valid Back-Channel Logout token: end the Session Sid of User Sub.
type LogoutToken struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
}

// Verifier checks tokens issued by one Polaris issuer.
type Verifier struct {
	provider *oidc.Provider
	access   *oidc.IDTokenVerifier
}

// NewVerifier fetches issuer's discovery document. audience is the API's
// identifier; access tokens for any other API are refused.
func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("polaris: %w", err)
	}
	return &Verifier{provider: p, access: p.Verifier(rs256(audience))}, nil
}

func rs256(aud string) *oidc.Config {
	return &oidc.Config{ClientID: aud, SupportedSigningAlgs: []string{oidc.RS256}}
}

// VerifyAccessToken checks signature, iss, aud, typ at+jwt and exp.
func (v *Verifier) VerifyAccessToken(ctx context.Context, raw string) (*Claims, error) {
	var c Claims
	if err := verify(ctx, v.access, raw, "at+jwt", &c); err != nil {
		return nil, err
	}
	if c.Sub == "" || c.ClientID == "" {
		return nil, errors.New("polaris: access token without sub or client_id")
	}
	return &c, nil
}

const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken checks a Back-Channel Logout logout_token sent to the
// Application clientID (OIDC Back-Channel Logout 1.0, 2.6).
func (v *Verifier) VerifyLogoutToken(ctx context.Context, clientID, raw string) (*LogoutToken, error) {
	var c struct {
		LogoutToken
		Iat    *int64                     `json:"iat"`
		Jti    string                     `json:"jti"`
		Nonce  *json.RawMessage           `json:"nonce"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := verify(ctx, v.provider.Verifier(rs256(clientID)), raw, "logout+jwt", &c); err != nil {
		return nil, err
	}
	ev, ok := c.Events[backChannelLogoutEvent]
	switch {
	case !ok || !strings.HasPrefix(strings.TrimSpace(string(ev)), "{"):
		return nil, errors.New("polaris: logout token without the back-channel logout event")
	case c.Nonce != nil:
		return nil, errors.New("polaris: logout token with a nonce")
	case c.Sub == "" || c.Sid == "": // Polaris always sends both
		return nil, errors.New("polaris: logout token without sub or sid")
	case c.Iat == nil || c.Jti == "":
		return nil, errors.New("polaris: logout token without iat or jti")
	}
	return &c.LogoutToken, nil
}

// verify checks raw with ov, then its typ header, then decodes its claims into dst.
func verify(ctx context.Context, ov *oidc.IDTokenVerifier, raw, typ string, dst any) error {
	tok, err := ov.Verify(ctx, raw)
	if err != nil {
		return fmt.Errorf("polaris: %w", err)
	}
	// go-oidc leaves typ alone; the signature is already checked, so this parse is safe.
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return fmt.Errorf("polaris: %w", err)
	}
	got, _ := jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
	if strings.TrimPrefix(strings.ToLower(got), "application/") != typ {
		return fmt.Errorf("polaris: token typ %q, want %q", got, typ)
	}
	if err := tok.Claims(dst); err != nil {
		return fmt.Errorf("polaris: %w", err)
	}
	return nil
}

type ctxKey struct{}

// FromContext returns the access token claims Require put on the request.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Require lets a request through only with a valid Bearer access token holding
// every one of entitlements: 401 when the token is missing or invalid, 403
// when an Entitlement is missing. For "any one of", check FromContext yourself.
func (v *Verifier) Require(next http.Handler, entitlements ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || raw == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "no access token", http.StatusUnauthorized)
			return
		}
		c, err := v.VerifyAccessToken(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid access token", http.StatusUnauthorized)
			return
		}
		var missing []string
		for _, e := range entitlements {
			if !slices.Contains(c.Entitlements, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			http.Error(w, "missing entitlements: "+strings.Join(missing, ", "), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}
