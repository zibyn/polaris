package login_test

import (
	"encoding/json"
	"net/url"
	"sync"
	"testing"
)

// redeem trades code at /token with codeVerifier; a failure comes back as the error code.
func (e *env) redeem(code, codeVerifier string) (tokens, string) {
	e.t.Helper()
	_, body := e.do("POST", "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback},
		"client_id": {clientID}, "code_verifier": {codeVerifier},
	})
	var out struct {
		tokens
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return out.tokens, out.Error
}

func (e *env) passwordCode() string {
	e.t.Helper()
	_, page := e.authorize("")
	resp, _ := e.submit(page, "owner", "password1")
	return e.code(resp)
}

func TestAuthCodeConcurrentRedemptionOneWins(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	code := e.passwordCode()

	const n = 8
	type result struct {
		tok     tokens
		errCode string
	}
	results := make(chan result, n)
	var ready sync.WaitGroup
	ready.Add(1)
	for range n {
		go func() {
			ready.Wait()
			tok, errCode := e.redeem(code, verifier)
			results <- result{tok, errCode}
		}()
	}
	ready.Done()
	ok := 0
	for range n {
		r := <-results
		switch {
		case r.errCode == "" && r.tok.AccessToken != "":
			ok++
		case r.errCode != "invalid_grant":
			t.Errorf("losing redemption got %q, want invalid_grant", r.errCode)
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded, want 1", ok, n)
	}
}

func TestAuthCodeBurnsOnWrongVerifier(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	code := e.passwordCode()

	if _, errCode := e.redeem(code, "wrong-verifier-wrong-verifier-wrong-verifier-00"); errCode == "" {
		t.Fatal("wrong verifier redeemed the code")
	}
	if tok, errCode := e.redeem(code, verifier); errCode != "invalid_grant" || tok.AccessToken != "" {
		t.Fatalf("retry with the right verifier: %q, want invalid_grant", errCode)
	}
}
