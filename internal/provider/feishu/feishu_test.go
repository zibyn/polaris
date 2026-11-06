package feishu_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/feishu"
)

const cb = "https://auth.example/cb"

// fake is a Feishu upstream: it hands out code "c" at its authorization
// endpoint, and a test sets what its user_info answers.
type fake struct {
	auth     url.Values     // last authorization request
	tokenReq map[string]any // last token request body
	userinfo any
	tokenErr bool
}

func start(t *testing.T, e *feishu.Endpoints) *fake {
	t.Helper()
	f := &fake{userinfo: map[string]any{"code": 0, "data": map[string]any{"union_id": "on_1", "open_id": "ou_1",
		"name": "张三", "avatar_big": "https://cdn.example/a.png", "email": "typed@example.com",
		"enterprise_email": "zhangsan@corp.example", "mobile": "+8613800138000"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Errorf("token content type %q", r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&f.tokenReq)
		sum := sha256.Sum256([]byte(f.tokenReq["code_verifier"].(string)))
		if f.tokenErr || f.tokenReq["code"] != "c" || f.tokenReq["client_secret"] != "shh" ||
			f.tokenReq["redirect_uri"] != f.auth.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != f.auth.Get("code_challenge") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":20049,"error":"invalid_grant","error_description":"PKCE 校验失败"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"access_token":"at","token_type":"Bearer"}`))
	})
	mux.HandleFunc("GET /user_info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":99991663,"msg":"invalid token"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(f.userinfo)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	old := *e
	*e = feishu.Endpoints{Authorize: ts.URL + "/authorize", Token: ts.URL + "/token", Userinfo: ts.URL + "/user_info"}
	t.Cleanup(func() { *e = old })
	return f
}

func signIn(t *testing.T, key string, f *fake) (provider.Identity, error) {
	t.Helper()
	p, err := provider.GetType(key).New(map[string]string{"client_id": "cli_1", "client_secret": "shh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(provider.NoReauthPrompt); !ok {
		t.Errorf("%s can ask for no fresh sign-in", key)
	}
	authURL, err := p.AuthURL(context.Background(), cb, "st", "n", "verifier-verifier-verifier-verifier-verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	f.auth = u.Query()
	return p.Callback(context.Background(), url.Values{"code": {"c"}, "state": {"st"}}, cb, "n", "verifier-verifier-verifier-verifier-verifier")
}

func TestFeishuSignsInAsTheUnionID(t *testing.T) {
	for _, tc := range []struct {
		key string
		e   *feishu.Endpoints
	}{{"feishu", &feishu.Feishu}, {"lark", &feishu.Lark}} {
		t.Run(tc.key, func(t *testing.T) {
			f := start(t, tc.e)
			id, err := signIn(t, tc.key, f)
			if err != nil {
				t.Fatal(err)
			}
			want := provider.Identity{Subject: "on_1", Email: "zhangsan@corp.example", Phone: "+8613800138000",
				Name: "张三", Picture: "https://cdn.example/a.png"}
			if id != want {
				t.Errorf("signed in as %+v", id)
			}
			q := f.auth
			if q.Get("response_type") != "code" || q.Get("client_id") != "cli_1" || q.Get("code_challenge_method") != "S256" ||
				q.Get("state") != "st" || q.Get("scope") != "contact:user.employee:readonly contact:user.phone:readonly" {
				t.Errorf("authorization request: %v", q)
			}
			if f.tokenReq["grant_type"] != "authorization_code" || f.tokenReq["client_id"] != "cli_1" {
				t.Errorf("token request: %v", f.tokenReq)
			}
		})
	}
}

func TestFeishuRefusesWhatItCannotTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*fake)
		want string
	}{
		"token error": {func(f *fake) { f.tokenErr = true }, "PKCE 校验失败"},
		"resigned":    {func(f *fake) { f.userinfo = map[string]any{"code": 20021, "msg": "user resigned"} }, "离职"},
		"frozen":      {func(f *fake) { f.userinfo = map[string]any{"code": 20022, "msg": "user frozen"} }, "冻结"},
		"other code":  {func(f *fake) { f.userinfo = map[string]any{"code": 20010, "msg": "no permission"} }, "no permission"},
		"no union_id": {func(f *fake) { f.userinfo = map[string]any{"code": 0, "data": map[string]any{"open_id": "ou_1"}} }, "union_id"},
	} {
		t.Run(name, func(t *testing.T) {
			f := start(t, &feishu.Feishu)
			tc.set(f)
			_, err := signIn(t, "feishu", f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}
