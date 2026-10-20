// Package appletest is a fake Sign in with Apple for tests: its token
// endpoint exchanges the codes it approves, and its revoke endpoint records
// what it was asked to revoke.
package appletest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zibyn/polaris/internal/provider/apple"
)

const (
	TeamID     = "TEAM123456"
	KeyID      = "KEY1234567"
	ServicesID = "com.example.web"
	BundleID   = "com.example.app"
)

// Fake is Apple, signing everyone in as Sub.
type Fake struct {
	t   *testing.T
	key *ecdsa.PrivateKey
	Sub string
	// FailToken and FailRevoke make those endpoints answer 400.
	FailToken, FailRevoke bool
	// NoExp leaves exp out of the id_token.
	NoExp bool

	mu    sync.Mutex
	codes map[string]url.Values // code → the authorization request
	// ClientSecrets are the claims of each client secret JWT received.
	ClientSecrets []map[string]any
	// Revoked are the forms posted to the revoke endpoint.
	Revoked []url.Values
}

// Start runs a fake Apple and points the Apple Provider type at it.
func Start(t *testing.T) *Fake {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fake{t: t, key: key, Sub: "001234.apple-user.0001", codes: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/token", f.token)
	mux.HandleFunc("POST /auth/revoke", f.revoke)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	old := apple.Endpoint
	apple.Endpoint = ts.URL
	t.Cleanup(func() { apple.Endpoint = old })
	return f
}

// Config is the settings of an Apple Provider for this fake, its key as
// pasted into a one-line input.
func (f *Fake) Config() map[string]string {
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	p8 := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "\n", " ")
	return map[string]string{"team_id": TeamID, "key_id": KeyID, "private_key": p8, "services_id": ServicesID, "bundle_id": BundleID}
}

// Approve is the User signing in at authURL; it returns the form Apple
// posts back to the redirect_uri, with the name and email Apple adds on a
// first sign-in.
func (f *Fake) Approve(authURL string) url.Values {
	f.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_mode") != "form_post" || q.Get("response_type") != "code" || q.Has("scope") || q.Get("client_id") != ServicesID {
		f.t.Errorf("authorization request: %v", q)
	}
	code := rand.Text()
	f.mu.Lock()
	f.codes[code] = q
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")},
		"user": {`{"name":{"firstName":"Ann","lastName":"Lee"},"email":"ann@privaterelay.appleid.com"}`}}
}

// NativeCode is the User signing in with Sign in with Apple in the iOS
// App: it returns the authorization_code the App gets, issued to the
// Bundle ID with no redirect_uri or nonce.
func (f *Fake) NativeCode() string {
	code := rand.Text()
	f.mu.Lock()
	f.codes[code] = url.Values{"client_id": {BundleID}}
	f.mu.Unlock()
	return code
}

// clientSecret checks the client secret JWT of r against the .p8 key and
// records its claims.
func (f *Fake) clientSecret(w http.ResponseWriter, r *http.Request) bool {
	tok, err := jwt.ParseSigned(r.PostFormValue("client_secret"), []jose.SignatureAlgorithm{jose.ES256})
	claims := map[string]any{}
	if err == nil {
		err = tok.Claims(&f.key.PublicKey, &claims)
	}
	if err != nil || tok.Headers[0].KeyID != KeyID {
		f.t.Errorf("client secret: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return false
	}
	f.mu.Lock()
	f.ClientSecrets = append(f.ClientSecrets, claims)
	f.mu.Unlock()
	return true
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	if !f.clientSecret(w, r) {
		return
	}
	f.mu.Lock()
	req, ok := f.codes[r.PostFormValue("code")]
	delete(f.codes, r.PostFormValue("code"))
	f.mu.Unlock()
	if f.FailToken || !ok || r.PostFormValue("grant_type") != "authorization_code" ||
		r.PostFormValue("client_id") != req.Get("client_id") || r.PostFormValue("redirect_uri") != req.Get("redirect_uri") {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	// The refresh token for code is "rt-<code>". Apple signs the id_token
	// with RS256; Polaris trusts the TLS response instead.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key}, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": "https://appleid.apple.com", "aud": req.Get("client_id"), "sub": f.Sub,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "nonce": req.Get("nonce"),
		"email": "ann@privaterelay.appleid.com",
	}
	if f.NoExp {
		delete(claims, "exp")
	}
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		"refresh_token": "rt-" + r.PostFormValue("code"), "id_token": idToken,
	})
}

func (f *Fake) revoke(w http.ResponseWriter, r *http.Request) {
	if !f.clientSecret(w, r) {
		return
	}
	f.mu.Lock()
	f.Revoked = append(f.Revoked, r.PostForm)
	f.mu.Unlock()
	if f.FailRevoke {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	}
}
