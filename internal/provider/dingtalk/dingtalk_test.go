package dingtalk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/dingtalk"
)

// fake is DingTalk's API: code "c" exchanges for token "at", and a test
// sets what users/me answers.
type fake struct {
	tokenReq map[string]string
	me       string // users/me's JSON
	status   int    // users/me's status
}

func start(t *testing.T) *fake {
	t.Helper()
	f := &fake{me: `{"unionId":"u1","openId":"o1","nick":"张三"}`, status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1.0/oauth2/userAccessToken", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&f.tokenReq)
		if r.Header.Get("Content-Type") != "application/json" || f.tokenReq["code"] != "c" ||
			f.tokenReq["clientId"] != "ding1" || f.tokenReq["clientSecret"] != "shh" || f.tokenReq["grantType"] != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"invalidAuthCode","message":"授权码无效"}`))
			return
		}
		_, _ = w.Write([]byte(`{"accessToken":"at","refreshToken":"rt","expireIn":7200}`))
	})
	mux.HandleFunc("GET /v1.0/contact/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-acs-dingtalk-access-token") != "at" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"InvalidAuthentication","message":"不合法的access_token"}`))
			return
		}
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.me))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	login, api := dingtalk.Login, dingtalk.API
	dingtalk.Login, dingtalk.API = ts.URL, ts.URL
	t.Cleanup(func() { dingtalk.Login, dingtalk.API = login, api })
	return f
}

func newDingTalk(t *testing.T) provider.Redirect {
	t.Helper()
	p, err := provider.GetType("dingtalk").New(map[string]string{"client_id": "ding1", "client_secret": "shh"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDingTalkAuthorizationRequest(t *testing.T) {
	start(t)
	p := newDingTalk(t)
	if _, ok := p.(provider.NoReauthPrompt); !ok {
		t.Error("dingtalk can ask for no fresh sign-in")
	}
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if u.Path != "/oauth2/auth" || q.Get("prompt") != "consent" || q.Get("scope") != "openid" || q.Get("response_type") != "code" ||
		q.Get("client_id") != "ding1" || q.Get("redirect_uri") != "https://auth.example/cb" || q.Get("state") != "st" ||
		q.Has("code_challenge") || q.Has("nonce") {
		t.Errorf("authorization request: %s", authURL)
	}
}

// Either name DingTalk gives the code signs in, as the unionId.
func TestDingTalkSignsInAsTheUnionID(t *testing.T) {
	for _, params := range []url.Values{{"authCode": {"c"}}, {"code": {"c"}}, {"authCode": {"c"}, "code": {"c"}}} {
		start(t)
		id, err := newDingTalk(t).Callback(context.Background(), params, "https://auth.example/cb", "n", "verifier")
		if err != nil {
			t.Fatalf("%v: %v", params, err)
		}
		if id.Subject != "u1" {
			t.Errorf("%v: signed in as %+v", params, id)
		}
	}
}

func TestDingTalkRefusesWhatItCannotTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		params url.Values
		set    func(*fake)
		want   string
	}{
		"denied":     {url.Values{"error": {"access_denied"}}, func(*fake) {}, "access_denied"},
		"bad code":   {url.Values{"authCode": {"x"}}, func(*fake) {}, "授权码无效"},
		"no unionId": {url.Values{"authCode": {"c"}}, func(f *fake) { f.me = `{"openId":"o1"}` }, "unionId"},
		"users/me 403": {url.Values{"authCode": {"c"}}, func(f *fake) {
			f.status, f.me = http.StatusForbidden, `{"code":"Forbidden.AccessDenied","message":"应用尚未开通所需的权限"}`
		}, "应用尚未开通所需的权限"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.set(start(t))
			_, err := newDingTalk(t).Callback(context.Background(), tc.params, "https://auth.example/cb", "n", "verifier")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}
