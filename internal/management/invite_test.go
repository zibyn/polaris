package management_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/identity"
)

// outbox is a Webhook email Channel endpoint: it keeps the last 注册邀请 the
// mail carried, so a test can follow the link the recipient would click.
// fail makes it answer 502, standing in for a mail server that is down.
type outbox struct {
	mu   sync.Mutex
	to   string
	link string
	fail bool
}

func (o *outbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p struct{ To, Link string }
	_ = json.NewDecoder(r.Body).Decode(&p)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		http.Error(w, "mail server down", http.StatusBadGateway)
		return
	}
	o.to, o.link = p.To, p.Link
}

func (o *outbox) last() (to, link string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.to, o.link
}

// mailer enables the email Channel, pointed at a receiver this test owns.
func (e *env) mailer() *outbox {
	e.t.Helper()
	o := &outbox{}
	ts := httptest.NewServer(o)
	e.t.Cleanup(ts.Close)
	if err := channel.NewStore(e.pool, e.keyring).Put(context.Background(), "email", "webhook",
		map[string]string{"url": ts.URL, "secret": "s"}); err != nil {
		e.t.Fatal(err)
	}
	return o
}

// inviteState is the Management API's invite field on a User: what happened
// to their 注册邀请, and until when a link that is out there works.
type inviteState struct {
	State     string
	ExpiresAt *time.Time
}

// tokenOf pulls the invite token out of a link.
func tokenOf(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "/invite?token=")
	if !ok || token == "" {
		t.Fatalf("no invite link: %q", link)
	}
	return token
}

// invitesIn counts the invite rows whose token hashes to token.
func (e *env) invitesIn(token string) int {
	e.t.Helper()
	sum := sha256.Sum256([]byte(token))
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM invites WHERE token_hash = $1", sum[:]).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// 创建时能直接发出注册邀请: 邮箱必填, 账号待激活、一个密码都没有, 链接当场
// 寄出去, 审计里「发出」的操作人是管理员、「创建」的是同一个账号。
func TestCreateUserWithAnInvite(t *testing.T) {
	e := start(t)
	mail := e.mailer()
	owner := e.token(e.owner, nil)

	var created struct {
		Sub     string
		Pending bool
	}
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "Alice@Example.com", "invite": true}, &created); code != 200 {
		t.Fatalf("create with an invite: %d", code)
	}
	if !created.Pending {
		t.Error("an invited User is not 待激活")
	}
	if to, link := mail.last(); to != "alice@example.com" || !strings.Contains(link, "/invite?token=") {
		t.Fatalf("the mail carried %q %q", to, link)
	} else if e.invitesIn(tokenOf(t, link)) != 1 {
		t.Error("the link that went out is not the one on file")
	}
	// 管理员没有密码可给: 这个账号一条凭据都没有。
	var detail struct{ HasPassword bool }
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 || detail.HasPassword {
		t.Errorf("get: %d, hasPassword %v", code, detail.HasPassword)
	}
	if ev := e.audited("user.created"); ev.Sub != created.Sub || ev.ByUser != "owner" {
		t.Errorf("user.created: %+v", ev)
	}
	// 发出的操作人是管理员; 关于的人是被邀请的那个账号。
	if ev := e.audited("invite.sent"); ev.Sub != created.Sub || ev.ByUser != "owner" || ev.Detail["by"] != e.owner {
		t.Errorf("invite.sent 的操作人该是管理员: %+v", ev)
	}
}

// 「初始密码」与「发注册邀请」互斥, 而且必须选一个: 都没有的待激活账号除了
// 注销按钮没有任何入口。
func TestCreateUserNeedsExactlyOneWayIn(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	for name, body := range map[string]map[string]any{
		"both":    {"identifier": "a@example.com", "password": "password1", "invite": true},
		"neither": {"identifier": "a@example.com"},
	} {
		var problem struct{ Detail string }
		if code := e.call("POST", owner, "/users", body, &problem); code != 422 || problem.Detail == "" {
			t.Errorf("%s: %d %+v", name, code, problem)
		}
	}
	var list struct{ Users []user }
	if code := e.get(owner, "/users", &list); code != 200 || len(subs(list.Users)) != 1 {
		t.Errorf("a rejected create made a User anyway: %v", subs(list.Users))
	}
}

// 邀请只支持邮箱: 用户名或手机号建号时选了「发注册邀请」被拒, 并说明原因。
func TestInviteIsEmailOnly(t *testing.T) {
	e := start(t)
	e.mailer()
	owner := e.token(e.owner, nil)
	for _, id := range []string{"alice", "+8613800001111"} {
		var problem struct{ Detail string }
		if code := e.call("POST", owner, "/users", map[string]any{"identifier": id, "invite": true}, &problem); code != 422 {
			t.Errorf("%s: %d", id, code)
		} else if problem.Detail != identity.ErrInviteNeedsEmail.Error() {
			t.Errorf("%s: %q", id, problem.Detail)
		}
	}
	// 没有邮箱的已有 User 也一样, 拒绝时说的是这个原因。
	e.user("BOB", nil, "username:bobby")
	var problem struct{ Detail string }
	if code := e.call("POST", owner, "/users/BOB/invite", nil, &problem); code != 422 {
		t.Errorf("invite a User with no email: %d", code)
	} else if problem.Detail != identity.ErrNoEmail.Error() {
		t.Errorf("detail: %q", problem.Detail)
	}
}

// 没有配邮箱渠道就发不出去: 说的是这件事, 不是"发送失败"。
func TestInviteWithoutAnEmailChannel(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	var created struct{ Sub string }
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "password": "password1"}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	var problem struct{ Detail string }
	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, &problem); code != 422 {
		t.Errorf("no email Channel: %d", code)
	} else if problem.Detail == "" {
		t.Error("no reason given")
	}
}

// 重发替换旧 token: 旧链接立即失效, 表里仍然只有一条。
func TestResendReplacesTheOldLink(t *testing.T) {
	e := start(t)
	mail := e.mailer()
	owner := e.token(e.owner, nil)
	var created struct{ Sub string }
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "invite": true}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	_, first := mail.last()
	old := tokenOf(t, first)

	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("resend: %d", code)
	}
	_, second := mail.last()
	if second == first {
		t.Fatal("the resent link is the same one")
	}
	if e.invitesIn(old) != 0 {
		t.Error("the replaced link still works")
	}
	if e.invitesIn(tokenOf(t, second)) != 1 {
		t.Error("the new link is not on file")
	}
	var rows int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM invites WHERE user_id = $1", created.Sub).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("invite rows = %d, want 1 (%v)", rows, err)
	}
	// 两封都算「发出」, 操作人都是管理员。
	if evs := e.events("event=invite.sent&sub=" + created.Sub); len(evs) != 2 || evs[0].ByUser != "owner" || evs[0].Detail["by"] != e.owner {
		t.Errorf("invite.sent events: %+v", evs)
	}
}

// 撤销后链接立即不可用; 撤销一条本来就没有的邀请不算一次撤销, 也不留审计。
func TestRevokeTakesTheLinkBack(t *testing.T) {
	e := start(t)
	mail := e.mailer()
	owner := e.token(e.owner, nil)
	var created struct{ Sub string }
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "invite": true}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	_, link := mail.last()

	if code := e.call("DELETE", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if e.invitesIn(tokenOf(t, link)) != 0 {
		t.Error("the revoked link is still on file")
	}
	if ev := e.audited("invite.revoked"); ev.Sub != created.Sub || ev.ByUser != "owner" || ev.Detail["by"] != e.owner {
		t.Errorf("invite.revoked: %+v", ev)
	}
	if code := e.call("DELETE", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("revoke nothing: %d", code)
	}
	if evs := e.events("event=invite.revoked&sub=" + created.Sub); len(evs) != 1 {
		t.Errorf("revoking nothing was audited: %+v", evs)
	}
}

// 发信失败不留可用 token: 那条刚铸出来的随即删掉, 表里干干净净。账号本身
// 留着 —— 管理员在用户页重发即可。
func TestAFailedSendLeavesNoUsableLink(t *testing.T) {
	e := start(t)
	mail := e.mailer()
	mail.fail = true
	owner := e.token(e.owner, nil)
	ctx := context.Background()

	var created struct{ Sub string }
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "password": "password1"}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	var problem struct{ Detail string }
	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, &problem); code != 422 {
		t.Fatalf("send with the mail server down: %d", code)
	}
	if problem.Detail != "邀请邮件发送失败,请稍后再试" {
		t.Errorf("detail: %q", problem.Detail)
	}
	var rows int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM invites WHERE user_id = $1", created.Sub).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("a failed send left %d invites", rows)
	}
	// 没有一次「发出」被记下来, 因为这封没有发出去。
	if evs := e.events("event=invite.sent&sub=" + created.Sub); len(evs) != 0 {
		t.Errorf("a failed send was audited as sent: %+v", evs)
	}

	// 创建时就带着邀请的那条路一样: 账号建好了(在用户列表里找得到, 重发即可),
	// 但一条可用链接都没有。
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "bob@example.com", "invite": true}, &problem); code != 422 {
		t.Fatalf("create with an invite while the mail server is down: %d", code)
	}
	// 说的是「账号已经建好」而不是光说邮件失败: 否则管理员会当它没建成再点一次,
	// 那次撞上 409「已属于另一个 User」。
	if !strings.Contains(problem.Detail, "账号已经建好") {
		t.Errorf("没有说账号已经建好: %q", problem.Detail)
	}
	var list struct{ Users []user }
	if code := e.get(owner, "/users?q=bob@example.com", &list); code != 200 || len(list.Users) != 1 {
		t.Fatalf("the account is not there to re-send from: %v", subs(list.Users))
	}
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM invites WHERE user_id = $1", list.Users[0].Sub).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("a failed send left %d invites", rows)
	}
}

// 密码登录关着的时候两条路都走不通: 设出来的密码登录不了, 也就没有意义。
func TestInviteNeedsPasswordLoginOn(t *testing.T) {
	e := start(t)
	e.mailer()
	owner := e.token(e.owner, nil)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'off'"); err != nil {
		t.Fatal(err)
	}
	var problem struct{ Detail string }
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "password": "password1"}, &problem); code != 422 || problem.Detail == "" {
		t.Errorf("an initial password with 密码登录 off: %d %+v", code, problem)
	}
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "bob@example.com", "invite": true}, &problem); code != 422 || problem.Detail == "" {
		t.Errorf("an invite with 密码登录 off: %d %+v", code, problem)
	}
}

// 邀请是 users:write 的动作, 也和别的动作一样不能动管理员。
func TestInviteNeedsTheWritePermission(t *testing.T) {
	e := start(t)
	e.mailer()
	e.user("READONLY", []string{"readonly"}, "email:readonly@example.com")
	e.user("ADMIN", []string{"admin"}, "email:admin@example.com")

	readonly := e.token("READONLY", nil)
	if code := e.call("POST", readonly, "/users/ADMIN/invite", nil, nil); code != 403 {
		t.Errorf("readonly sent an invite: %d", code)
	}
	// admin 角色有 users:write, 但没有 admin-roles:assign, 所以动不了管理员。
	admin := e.token("ADMIN", nil)
	if code := e.call("POST", admin, "/users/"+e.owner+"/invite", nil, nil); code != 403 {
		t.Errorf("an admin invited an admin: %d", code)
	}
	if code := e.call("DELETE", readonly, "/users/ADMIN/invite", nil, nil); code != 403 {
		t.Errorf("readonly revoked an invite: %d", code)
	}
}

// 用户详情说得出注册邀请现在是什么状态: 没发出 / 已发出(到什么时候过期) /
// 已接受 —— 管理端据此显示状态并决定给哪几个按钮。
func TestUserDetailShowsTheInviteState(t *testing.T) {
	e := start(t)
	mail := e.mailer()
	owner := e.token(e.owner, nil)
	ctx := context.Background()

	var created struct {
		Sub    string
		Invite inviteState
	}
	if code := e.call("POST", owner, "/users", map[string]any{"identifier": "alice@example.com", "password": "password1"}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	if created.Invite.State != "none" {
		t.Errorf("一个没被邀请过的账号: %+v", created.Invite)
	}
	// 对已有的 User 发出邀请。
	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("send: %d", code)
	}
	var detail struct{ Invite inviteState }
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 {
		t.Fatalf("get: %d", code)
	}
	if detail.Invite.State != "sent" {
		t.Fatalf("发出之后: %+v", detail.Invite)
	}
	// 7 天有效, 详情要说得出是什么时候。
	if d := detail.Invite.ExpiresAt; d == nil {
		t.Error("已发出的邀请没有说过期时间")
	} else if until := time.Until(*d); until < 6*24*time.Hour || until > 7*24*time.Hour {
		t.Errorf("过期时间是 %v 之后", until)
	}
	// 撤销之后又回到「没发出」, 也没有过期时间了。
	if code := e.call("DELETE", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	detail.Invite = inviteState{}
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 {
		t.Fatalf("get after revoking: %d", code)
	}
	if detail.Invite.State != "none" || detail.Invite.ExpiresAt != nil {
		t.Errorf("撤销之后: %+v", detail.Invite)
	}

	// 过期的链接不算「已发出」: 清理任务一小时才扫一次, 不能等到那时候才改口,
	// 否则页面上会写「已发出 · <一个已经过去的时刻> 过期」。
	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("send: %d", code)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE invites SET expires_at = now() - interval '1 hour' WHERE user_id = $1", created.Sub); err != nil {
		t.Fatal(err)
	}
	detail.Invite = inviteState{}
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 {
		t.Fatalf("get after the link expired: %d", code)
	}
	if detail.Invite.State != "none" || detail.Invite.ExpiresAt != nil {
		t.Errorf("链接过期之后: %+v", detail.Invite)
	}

	// 本人把链接用掉之后是「已接受」。
	if code := e.call("POST", owner, "/users/"+created.Sub+"/invite", nil, nil); code != 204 {
		t.Fatalf("send again: %d", code)
	}
	_, link := mail.last()
	if _, err := e.ids.AcceptInvite(ctx, tokenOf(t, link), "her-own-password"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	detail.Invite = inviteState{}
	if code := e.get(owner, "/users/"+created.Sub, &detail); code != 200 {
		t.Fatalf("get after accepting: %d", code)
	}
	if detail.Invite.State != "accepted" {
		t.Errorf("接受之后: %+v", detail.Invite)
	}
}
