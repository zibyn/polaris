package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

// invited mints a 注册邀请 for a fresh account and returns its sub and the
// token the mail would carry.
func (e *env) invited(identifier string) (sub, token string) {
	e.t.Helper()
	ctx := context.Background()
	sub, err := e.ids.CreateInvitedUser(ctx, identifier)
	if err != nil {
		e.t.Fatal(err)
	}
	token, _, err = e.ids.MintInvite(ctx, sub)
	if err != nil {
		e.t.Fatal(err)
	}
	return sub, token
}

// 邀请接受页走登录页那套视觉规范 (星云品牌区 + 最宽 340px 的表单区), 设完
// 密码当场建立 Session 并回到 Application —— 不用再登一次 (ADR 0016)。
func TestAcceptingAnInviteSignsTheUserIn(t *testing.T) {
	e := start(t)
	sub, token := e.invited("Alice@Example.com")

	resp, page := e.do("GET", "/invite?token="+token, nil)
	if resp.StatusCode != 200 || !strings.Contains(page, `class="brand"`) || !strings.Contains(page, "max-width: 340px") {
		t.Fatalf("邀请接受页没走共用视觉规范: %d", resp.StatusCode)
	}
	for _, want := range []string{`name="password"`, `minlength="8"`, `value="` + token + `"`} {
		if !strings.Contains(page, want) {
			t.Errorf("no %s in:\n%s", want, page)
		}
	}
	// 邀请邮件里没有验证码, 页面上也就没有验证码那一套。
	if strings.Contains(page, "验证码") {
		t.Errorf("the accept page talks about codes:\n%s", page)
	}

	resp, _ = e.do("POST", "/invite", url.Values{"token": {token}, "password": {"her-own-password"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("accept: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !e.hasSessionCookie() {
		t.Fatal("no Session was started")
	}
	// 密码是她自己的, 账号不再是待激活。
	if who, err := e.ids.CheckPassword(context.Background(), identity.Attempt{}, "alice@example.com", "her-own-password"); err != nil || who != sub {
		t.Errorf("the password she set does not work: %q %v", who, err)
	}
	if pending, err := e.ids.Pending(context.Background(), sub); err != nil || pending {
		t.Errorf("still 待激活: %v %v", pending, err)
	}

	// 回到 Application: 带着这个 Session 走一次授权, 不再要求登录。
	resp, _ = e.authorize("")
	if resp.StatusCode/100 != 3 {
		t.Fatalf("asked to log in again: %d", resp.StatusCode)
	}
	claims := e.idToken(e.code(resp))
	if claims["sub"] != sub {
		t.Errorf("sub = %v, want %s", claims["sub"], sub)
	}
	// 链接证明的是邮箱的控制权, 和邮箱收到一个验证码是同一种证据。
	if amr, _ := claims["amr"].([]any); !contains(amr, "otp") {
		t.Errorf("amr = %v, want otp", claims["amr"])
	}
}

// 链接证明的是邮箱的控制权,和邮箱收到一个验证码一样多,所以它换来的不能比
// 验证码登录更多:开了两步验证的人接受邀请,密码照设,但拿不到 Session ——
// 还是要照常登录、输 TOTP 才进得去。
func TestAcceptingAnInviteDoesNotSkipTOTP(t *testing.T) {
	e := start(t)
	sub, token := e.invited("erin@example.com")
	e.twoFactor(sub)

	resp, _ := e.do("POST", "/invite", url.Values{"token": {token}, "password": {"her-own-password"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("accept: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.hasSessionCookie() {
		t.Error("邀请链接把两步验证绕过去了")
	}
	// 密码确实是她自己的,接下来照常登录即可。
	if who, err := e.ids.CheckPassword(context.Background(), identity.Attempt{}, "erin@example.com", "her-own-password"); err != nil || who != sub {
		t.Errorf("the password she set does not work: %q %v", who, err)
	}
	if pending, err := e.ids.Pending(context.Background(), sub); err != nil || pending {
		t.Errorf("still 待激活: %v %v", pending, err)
	}
}

// 用过、被撤销、已过期、根本不存在的链接, 一律给出同一句人话并指向管理员;
// 说的是这件事, 不是发码失败那套文案。
func TestAnInviteLinkThatIsNoGood(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	_, token := e.invited("bob@example.com")
	const spent = "这个邀请链接已失效或已过期,请联系管理员重新发送"

	noGood := func(what, token string) {
		t.Helper()
		resp, page := e.do("GET", "/invite?token="+token, nil)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(page, spent) {
			t.Errorf("%s: GET %d, want the admin-pointing message:\n%s", what, resp.StatusCode, page)
		}
		resp, page = e.do("POST", "/invite", url.Values{"token": {token}, "password": {"her-own-password"}})
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(page, spent) {
			t.Errorf("%s: POST %d, want the admin-pointing message:\n%s", what, resp.StatusCode, page)
		}
	}

	noGood("no such token", "nonsense")

	// 用过: 一次就够, 第二条链接也留不下。
	if resp, _ := e.do("POST", "/invite", url.Values{"token": {token}, "password": {"her-own-password"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("accept: %d", resp.StatusCode)
	}
	noGood("spent", token)

	// 撤销。
	carol, revoked := e.invited("carol@example.com")
	if _, err := e.ids.RevokeInvite(ctx, carol, "ADMIN"); err != nil {
		t.Fatal(err)
	}
	noGood("revoked", revoked)

	// 过期。
	dave, stale := e.invited("dave@example.com")
	if _, err := e.pool.Exec(ctx, "UPDATE invites SET expires_at = now() - interval '1 second' WHERE user_id = $1", dave); err != nil {
		t.Fatal(err)
	}
	noGood("expired", stale)
}
