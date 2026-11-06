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
	user     string // topapi/v2/user/get's JSON
}

func start(t *testing.T) *fake {
	t.Helper()
	f := &fake{me: `{"unionId":"u1","openId":"o1","nick":"张三"}`, status: http.StatusOK,
		user: `{"errcode":0,"result":{"name":"张三丰","avatar":"https://cdn.example/a.png","email":"typed@example.com",` +
			`"org_email":"zsf@corp.example","mobile":"13800138000","state_code":"86"}}`}
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
	mux.HandleFunc("POST /v1.0/oauth2/accessToken", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["appKey"] != "ding1" || req["appSecret"] != "shh" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"invalidClientIdOrSecret","message":"无效的clientId或者clientSecret"}`))
			return
		}
		_, _ = w.Write([]byte(`{"accessToken":"app","expireIn":7200}`))
	})
	mux.HandleFunc("POST /topapi/user/getbyunionid", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Query().Get("access_token") != "app" || req["unionid"] != "u1" {
			_, _ = w.Write([]byte(`{"errcode":60121,"errmsg":"找不到该用户"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0,"result":{"contact_type":0,"userid":"emp1"}}`))
	})
	mux.HandleFunc("POST /topapi/v2/user/get", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Query().Get("access_token") != "app" || req["userid"] != "emp1" {
			_, _ = w.Write([]byte(`{"errcode":60121,"errmsg":"找不到该用户"}`))
			return
		}
		_, _ = w.Write([]byte(f.user))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	login, api, oapi := dingtalk.Login, dingtalk.API, dingtalk.OAPI
	dingtalk.Login, dingtalk.API, dingtalk.OAPI = ts.URL, ts.URL, ts.URL
	t.Cleanup(func() { dingtalk.Login, dingtalk.API, dingtalk.OAPI = login, api, oapi })
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

// A new User brings what the organization's directory says, not the
// account's nickname: the org_email, never the typed-in email.
func TestDingTalkProfileIsTheDirectoryEntry(t *testing.T) {
	f := start(t)
	pr := newDingTalk(t).(provider.Profiler)
	id, err := pr.Profile(context.Background(), provider.Identity{Subject: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	want := provider.Identity{Subject: "u1", Email: "zsf@corp.example", Phone: "13800138000", Name: "张三丰", Picture: "https://cdn.example/a.png"}
	if id != want {
		t.Errorf("got %+v, want %+v", id, want)
	}

	// A phone outside China comes without its country code: left out.
	f.user = `{"errcode":0,"result":{"name":"Li","mobile":"5551234","state_code":"1"}}`
	if id, err := pr.Profile(context.Background(), provider.Identity{Subject: "u1"}); err != nil || id.Phone != "" {
		t.Errorf("foreign phone: %+v, %v", id, err)
	}

	// No directory access (the permission not granted) fails the sign-up.
	f.user = `{"errcode":60011,"errmsg":"没有调用该接口的权限"}`
	if _, err := pr.Profile(context.Background(), provider.Identity{Subject: "u1"}); err == nil || !strings.Contains(err.Error(), "60011") {
		t.Errorf("no permission: %v", err)
	}
}
