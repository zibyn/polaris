package wecom_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/wecom"
)

// fake is qyapi: gettoken hands out "at1", "at2", ... and getuserinfo
// answers what a test sets while the token is the latest one.
type fake struct {
	gettokens int // tokens handed out
	calls     int // gettoken requests, failed ones too
	userinfo  string
	expire    bool // the next getuserinfo answers 42001
}

func start(t *testing.T) *fake {
	t.Helper()
	f := &fake{userinfo: `{"errcode":0,"errmsg":"ok","userid":"ZhangSan"}`}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /cgi-bin/gettoken", func(w http.ResponseWriter, r *http.Request) {
		f.calls++
		if r.URL.Query().Get("corpid") != "ww1" || r.URL.Query().Get("corpsecret") != "shh" {
			_, _ = w.Write([]byte(`{"errcode":40001,"errmsg":"invalid credential"}`))
			return
		}
		f.gettokens++
		_, _ = fmt.Fprintf(w, `{"errcode":0,"errmsg":"ok","access_token":"at%d","expires_in":7200}`, f.gettokens)
	})
	mux.HandleFunc("GET /cgi-bin/auth/getuserinfo", func(w http.ResponseWriter, r *http.Request) {
		if f.expire || r.URL.Query().Get("access_token") != fmt.Sprintf("at%d", f.gettokens) {
			f.expire = false
			_, _ = w.Write([]byte(`{"errcode":42001,"errmsg":"access_token expired"}`))
			return
		}
		_, _ = w.Write([]byte(f.userinfo))
	})
	mux.HandleFunc("GET /cgi-bin/user/get", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != fmt.Sprintf("at%d", f.gettokens) || r.URL.Query().Get("userid") != "zhangsan" {
			_, _ = w.Write([]byte(`{"errcode":60111,"errmsg":"userid not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","userid":"zhangsan","name":"张三"}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	login, api := wecom.Login, wecom.API
	wecom.Login, wecom.API = ts.URL, ts.URL
	t.Cleanup(func() { wecom.Login, wecom.API = login, api })
	return f
}

func newWeCom(t *testing.T, secret string) provider.Redirect {
	t.Helper()
	p, err := provider.GetType("wecom").New(map[string]string{"corp_id": "ww1", "agent_id": "1000002", "secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func callback(p provider.Redirect) (provider.Identity, error) {
	return p.Callback(context.Background(), url.Values{"code": {"c"}, "state": {"st"}}, "https://auth.example/cb", "n", "v")
}

func TestWeComAuthorizationRequest(t *testing.T) {
	start(t)
	p := newWeCom(t, "shh")
	if _, ok := p.(provider.NoReauthPrompt); !ok {
		t.Error("wecom can ask for no fresh sign-in")
	}
	authURL, _ := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "v")
	u, _ := url.Parse(authURL)
	q := u.Query()
	if u.Path != "/wwlogin/sso/login" || q.Get("login_type") != "CorpApp" || q.Get("appid") != "ww1" ||
		q.Get("agentid") != "1000002" || q.Get("redirect_uri") != "https://auth.example/cb" || q.Get("state") != "st" || len(q) != 5 {
		t.Errorf("authorization request: %s", authURL)
	}
}

// Two logins fetch the app's access token once; one WeCom expired early is
// fetched again, once.
func TestWeComCachesTheAccessToken(t *testing.T) {
	f := start(t)
	p := newWeCom(t, "shh")
	for range 2 {
		id, err := callback(p)
		if err != nil {
			t.Fatal(err)
		}
		if id.Subject != "zhangsan" {
			t.Errorf("signed in as %+v", id)
		}
	}
	if f.gettokens != 1 {
		t.Errorf("gettoken called %d times", f.gettokens)
	}
	f.expire = true
	if _, err := callback(p); err != nil {
		t.Fatal(err)
	}
	if f.gettokens != 2 {
		t.Errorf("gettoken called %d times after expiry", f.gettokens)
	}
}

// A wrong secret is not retried at WeCom on every login: that would lock
// the corp out of gettoken.
func TestWeComBacksOffAFailedGettoken(t *testing.T) {
	f := start(t)
	p := newWeCom(t, "wrong")
	for range 3 {
		if _, err := callback(p); err == nil || !strings.Contains(err.Error(), "invalid credential") {
			t.Fatalf("err %v", err)
		}
	}
	if f.calls != 1 {
		t.Errorf("gettoken called %d times", f.calls)
	}
}

func TestWeComRefusesWhatItCannotTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		secret, userinfo, want string
	}{
		"not a member": {"shh", `{"errcode":0,"errmsg":"ok","openid":"oAAA"}`, "不是本企业成员"},
		"bad code":     {"shh", `{"errcode":40029,"errmsg":"invalid code"}`, "code 无效"},
		"bad domain":   {"shh", `{"errcode":50001,"errmsg":"redirect_url not authorised"}`, "可信域名"},
		"other":        {"shh", `{"errcode":60020,"errmsg":"not allow to access from your ip"}`, "not allow to access from your ip"},
		"bad secret":   {"wrong", "", "invalid credential"},
	} {
		t.Run(name, func(t *testing.T) {
			f := start(t)
			f.userinfo = tc.userinfo
			_, err := callback(newWeCom(t, tc.secret))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}

// A new User brings the member's name, and nothing user/get no longer gives.
func TestWeComProfileIsTheName(t *testing.T) {
	start(t)
	p := newWeCom(t, "shh")
	id, err := callback(p)
	if err != nil {
		t.Fatal(err)
	}
	id, err = p.(provider.Profiler).Profile(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if want := (provider.Identity{Subject: "zhangsan", Name: "张三"}); id != want {
		t.Errorf("got %+v, want %+v", id, want)
	}
	if _, err := p.(provider.Profiler).Profile(context.Background(), provider.Identity{Subject: "nobody"}); err == nil {
		t.Error("an unknown member got a profile")
	}
}
