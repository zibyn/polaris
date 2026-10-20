package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

// createPending makes a User the way an admin does (ADR 0016): an Identifier,
// an initial password of the admin's choosing, and 待激活.
func (e *env) createPending(identifier, password string) string {
	e.t.Helper()
	e.bootstrap("owner", "password1") // 引导关掉, 密码登录开着的实例
	sub, err := e.ids.CreatePendingUser(context.Background(), identifier, password)
	if err != nil {
		e.t.Fatal(err)
	}
	return sub
}

// pendingLogin is a User signing in at the hosted page with the initial
// password an admin set.
func (e *env) pendingLogin(username, password string) (*http.Response, string) {
	e.t.Helper()
	_, page := e.authorize("")
	return e.submit(page, username, password)
}

// 待激活的 User 用初始密码登录后被告知先设置密码; 改完才拿得到授权码,
// 在那之前拿不到任何令牌 (ADR 0016)。
func TestPendingUserMustSetAPasswordFirst(t *testing.T) {
	e := start(t)
	sub := e.createPending("alice@example.com", "initial-password")

	resp, page := e.pendingLogin("alice@example.com", "initial-password")
	if resp.StatusCode != 200 || !strings.Contains(page, "设置密码") || !strings.Contains(page, `name="password"`) {
		t.Fatalf("want the set-password page: %d %s", resp.StatusCode, page)
	}
	// 改密之前拿不到授权码: 页面不进下一步, 也没有 Session cookie.
	if e.hasSessionCookie() {
		t.Error("a Session was started before the password was set")
	}
	// 别的 op 一律不理会, 停在原处.
	resp, page = e.post(page, url.Values{"op": {"consent"}, "agree": {"1"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "设置密码") {
		t.Fatalf("another op got past the step: %d %s", resp.StatusCode, page)
	}

	// 太短的密码按现有规则拒绝, 且不激活.
	resp, page = e.post(page, url.Values{"op": {"set-password"}, "password": {"short"}})
	if resp.StatusCode != 200 || !strings.Contains(page, identity.ErrPasswordTooShort.Error()) {
		t.Fatalf("short password: %d %s", resp.StatusCode, page)
	}

	resp, _ = e.post(page, url.Values{"op": {"set-password"}, "password": {"her-own-password"}})
	// 设完即激活, 随后照常拿到授权码 (改完直接带着 code 跳回应用).
	claims := e.idToken(e.code(resp))
	if claims["sub"] != sub {
		t.Errorf("sub = %v, want %s", claims["sub"], sub)
	}
	if pending, err := e.ids.Pending(context.Background(), sub); err != nil || pending {
		t.Errorf("still 待激活: %v %v", pending, err)
	}

	// 新的密码能登录, 初始密码作废.
	e.newBrowser()
	resp, _ = e.pendingLogin("alice@example.com", "her-own-password")
	e.code(resp)
	e.newBrowser()
	if _, page := e.pendingLogin("alice@example.com", "initial-password"); !strings.Contains(page, identity.ErrBadCredentials.Error()) {
		t.Errorf("the initial password still works:\n%s", page)
	}
}

// 开了两步验证的待激活 User 也走得完 (ADR 0016): 强制改密排在两步验证之前,
// 而且走一条不要求近期重新认证的密码通路 —— 账号中心那条对 2FA 用户一律
// 拒绝密码和验证码, 用它会卡死。
func TestPendingUserWithTwoFactorGetsThrough(t *testing.T) {
	e := start(t)
	// 管理员没法在创建时开 2FA (那要求先激活), 所以直接把它给到库里,
	// 模拟「用户先开了 2FA, 后来又落进待激活」这个死结场景.
	sub := e.createPending("alice@example.com", "initial-password")
	secret, _ := e.twoFactor(sub)

	resp, page := e.pendingLogin("alice@example.com", "initial-password")
	if resp.StatusCode != 200 || !strings.Contains(page, "设置密码") {
		t.Fatalf("want the set-password page, not TOTP: %d %s", resp.StatusCode, page)
	}
	// 停在改密这一步: 不先改密就进不了 TOTP.
	if _, page := e.post(page, url.Values{"op": {"totp"}, "totp": {"000000"}}); !strings.Contains(page, "设置密码") {
		t.Fatalf("TOTP got in before the password was set:\n%s", page)
	}
	// 走完强制改密 —— 这正是不能复用账号中心改密接口的原因.
	resp, page = e.post(page, url.Values{"op": {"set-password"}, "password": {"her-own-password"}})
	if resp.StatusCode != 200 {
		t.Fatalf("set password with 2FA on: %d", resp.StatusCode)
	}
	// 改完密码接着是两步验证, 输对 TOTP 才拿到授权码.
	if !strings.Contains(page, "两步验证") {
		t.Fatalf("want the TOTP step after the password:\n%s", page)
	}
	if pending, _ := e.ids.Pending(context.Background(), sub); pending {
		t.Error("still 待激活: the password was not written")
	}
	resp, _ = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	claims := e.idToken(e.code(resp))
	if !contains(claims["amr"].([]any), "mfa") {
		t.Errorf("amr = %v, want mfa", claims["amr"])
	}
}

// 待激活期间改密与注销可用; 其它一律拒绝, 绑手机号与开两步验证被拒并说明
// 要先激活。
func TestPendingUserCanOnlySetAPasswordOrDelete(t *testing.T) {
	e := start(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}
	sub := e.createPending("alice@example.com", "initial-password")

	_, page := e.pendingLogin("alice@example.com", "initial-password")
	// 实例要求手机号, 但待激活挡在前面: 没有绑手机号这一步.
	if strings.Contains(page, "绑定手机号") {
		t.Errorf("the phone step came before the password:\n%s", page)
	}
	// 绕过这一步去发码、去开两步验证, 都被停在原处.
	for _, form := range []url.Values{
		{"op": {"send"}, "identifier": {"+8613800138000"}, "altcha": {e.solve()}},
		{"op": {"verify"}, "identifier": {"+8613800138000"}, "code": {"123456"}},
	} {
		resp, page := e.post(page, form)
		if resp.StatusCode != 200 || !strings.Contains(page, "设置密码") {
			t.Errorf("%v got past the step: %d", form, resp.StatusCode)
		}
	}
	// 账号中心那套 (改密码、绑手机号、开 2FA) 需要令牌, 而待激活拿不到令牌.
	if tok := e.pendingToken(sub); tok != "" {
		t.Errorf("a 待激活 User has a token: %s", tok)
	}

	// 注销可用, 而且把账号删干净.
	resp, page := e.post(page, url.Values{"op": {"delete-pending"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "账号已注销") {
		t.Fatalf("delete while 待激活: %d %s", resp.StatusCode, page)
	}
	if _, err := e.ids.SignIn(context.Background(), "email", "alice@example.com"); err != nil {
		t.Errorf("the Identifier is not free again: %v", err)
	}
}

// 待激活的 User 不给任何令牌: Application 侧看不到这个状态, 不加 claim、
// 不加 scope、ID token 不变。
func TestPendingUserGetsNoToken(t *testing.T) {
	e := start(t)
	sub := e.createPending("alice@example.com", "initial-password")

	if tok := e.pendingToken(sub); tok != "" {
		t.Errorf("a token was issued: %s", tok)
	}
	// 直连 API 与托管页一样: 改密之后才有 code.
	sent := e.challenge(url.Values{"username": {"alice@example.com"}, "password": {"initial-password"}, "altcha": {e.solve()}})
	if sent.Status != 403 || sent.Next != "password" || sent.AuthSession == "" {
		t.Fatalf("direct auth: %+v", sent)
	}
	done := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {"her-own-password"}})
	if done.Status != 200 || done.Code == "" {
		t.Fatalf("set password on the auth_session: %+v", done)
	}
	tok := e.exchange(clientID, "", done.Code)
	claims := e.claims(tok.IDToken)
	if claims["sub"] != sub {
		t.Errorf("sub = %v, want %s", claims["sub"], sub)
	}
	// ID token 里没有待激活的痕迹.
	for _, claim := range []string{"pending", "status", "active"} {
		if _, ok := claims[claim]; ok {
			t.Errorf("the ID token carries %q: %v", claim, claims)
		}
	}
}

// 直连 API: 待激活的 User 改密之前拿不到授权码, 别的下一步也进不去。
func TestDirectAuthPendingUser(t *testing.T) {
	e := start(t)
	e.createPending("alice@example.com", "initial-password")

	sent := e.challenge(url.Values{"username": {"alice@example.com"}, "password": {"initial-password"}, "altcha": {e.solve()}})
	if sent.Status != 403 || sent.Error != "insufficient_authorization" || sent.Next != "password" {
		t.Fatalf("password login: %+v", sent)
	}
	// 空密码: 停在原处.
	if r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {""}}); r.Status != 400 || r.Code != "" {
		t.Errorf("no password: %+v", r)
	}
	// 太短: 拒绝, 且不激活.
	if r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {"short"}}); r.Status != 400 {
		t.Errorf("short password: %+v", r)
	}
	// auth_session 还能用.
	done := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {"her-own-password"}})
	if done.Status != 200 || done.Code == "" {
		t.Fatalf("after setting the password: %+v", done)
	}
	// auth_session 用掉了.
	if r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {"again-again"}}); r.Error != "invalid_session" {
		t.Errorf("spent auth_session: %+v", r)
	}
}

// 待激活的 User 在直连 API 上也能注销账号: App 里的账号还没有令牌, 所以
// 就在这次登录里删掉 (ADR 0016)。
func TestDirectAuthPendingUserDeletes(t *testing.T) {
	e := start(t)
	sub := e.createPending("alice@example.com", "initial-password")

	sent := e.challenge(url.Values{"username": {"alice@example.com"}, "password": {"initial-password"}, "altcha": {e.solve()}})
	if sent.Next != "password" {
		t.Fatalf("password login: %+v", sent)
	}
	r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "delete": {"true"}})
	if r.Status != 400 || r.Error != "access_denied" {
		t.Fatalf("delete: %+v", r)
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE id = $1", sub).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows, want 0: the account survived", n)
	}
	// 标识符立刻释放, 同一个邮箱可以重新注册.
	if _, err := e.ids.SignIn(context.Background(), "email", "alice@example.com"); err != nil {
		t.Errorf("the Identifier is not free again: %v", err)
	}
	// 账号没了, auth_session 也随它作废.
	if again := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "password": {"her-own-password"}, "altcha": {e.solve()}}); again.Error != "invalid_session" {
		t.Errorf("auth_session after deletion: %+v", again)
	}
}

// 用 Provider 登录一个待激活的 User: 不给令牌, 并告知要设置密码。
func TestProviderLoginRefusedWhilePending(t *testing.T) {
	e := start(t)
	sub := e.createPending("alice@example.com", "initial-password")
	up := e.addGoogle()
	// 绑的是上游真正会报的那个 subject, 否则 Provider 登录会当成新用户建号.
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO external_identities (user_id, provider, subject) VALUES ($1, 'google', $2)`, sub, up.sub); err != nil {
		t.Fatal(err)
	}

	_, page := e.authorize("")
	callback := e.pressGoogle(page)
	// The Provider's callback signs nobody in on its own: it sends the
	// browser back to the login, which carries on with the pending step.
	resp, _ := e.do("GET", callback, nil)
	if resp.StatusCode/100 != 3 || !strings.Contains(resp.Header.Get("Location"), "/authorize/") {
		t.Fatalf("the callback did not send the browser back to the login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, page = e.do("GET", resp.Header.Get("Location"), nil)
	if resp.StatusCode != 200 || !strings.Contains(page, "设置密码") {
		t.Fatalf("Provider login while 待激活: %d %s", resp.StatusCode, page)
	}
	if e.hasSessionCookie() {
		t.Error("a Session was started by a Provider login")
	}
	// 改完密码才拿到授权码.
	resp, _ = e.post(page, url.Values{"op": {"set-password"}, "password": {"her-own-password"}})
	if claims := e.idToken(e.code(resp)); claims["sub"] != sub || !contains(claims["amr"].([]any), "fed") {
		t.Errorf("after the Provider login: %v", claims)
	}
}

// pendingToken reports the access token a 待激活 User can obtain, if any:
// the account center's, which is what every other interface needs.
func (e *env) pendingToken(sub string) string {
	e.t.Helper()
	// The only way to a token is an authorization code, and the only way to
	// one is a completed sign-in: ask the direct auth API for exactly that.
	sent := e.challenge(url.Values{"username": {"alice@example.com"}, "password": {"initial-password"}, "altcha": {e.solve()}})
	if sent.Code != "" {
		return e.exchange(clientID, "", sent.Code).AccessToken
	}
	return ""
}

func contains(hay []any, want string) bool {
	for _, v := range hay {
		if v == want {
			return true
		}
	}
	return false
}
