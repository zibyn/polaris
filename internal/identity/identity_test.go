package identity

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
)

func setup(t *testing.T) *Store {
	t.Helper()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return New(pool, keyring)
}

func TestBootstrap(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	token, err := s.SetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token: %q %v", token, err)
	}
	// Restarts and other replicas print the same token.
	if again, _ := s.SetupToken(ctx); again != token {
		t.Fatalf("token changed: %q -> %q", token, again)
	}

	for _, tc := range []struct {
		token, username, password string
		want                      error
	}{
		{"wrong", "root", "password1", ErrSetupToken},
		{token, "root", "short", ErrPasswordTooShort},
		{token, "密码八位密码八位", "password1", ErrUsername},
		{token, "a@b.c", "password1", ErrUsername},
	} {
		if _, err := s.Bootstrap(ctx, tc.token, tc.username, tc.password); !errors.Is(err, tc.want) {
			t.Errorf("Bootstrap(%q, %q, %q) = %v, want %v", tc.token, tc.username, tc.password, err, tc.want)
		}
	}

	// Eight characters, not eight bytes.
	sub, err := s.Bootstrap(ctx, token, "Root", "密码八位密码八位")
	if err != nil || sub == "" {
		t.Fatalf("bootstrap: %q %v", sub, err)
	}

	if _, err := s.Bootstrap(ctx, token, "other", "password1"); !errors.Is(err, ErrSetupClosed) {
		t.Errorf("second bootstrap: %v", err)
	}
	if tok, err := s.SetupToken(ctx); tok != "" || err != nil {
		t.Errorf("setup token after bootstrap: %q %v", tok, err)
	}

	// The owner logs in by password, the username case-insensitively.
	if got, err := s.CheckPassword(ctx, "root", "密码八位密码八位"); got != sub || err != nil {
		t.Errorf("CheckPassword = %q %v, want %q", got, err, sub)
	}
	for _, login := range []string{"ROOT", " root "} {
		if got, _ := s.CheckPassword(ctx, login, "密码八位密码八位"); got != sub {
			t.Errorf("login %q: %q", login, got)
		}
	}
	for _, tc := range [][2]string{{"root", "wrong-password"}, {"nobody", "密码八位密码八位"}} {
		if _, err := s.CheckPassword(ctx, tc[0], tc[1]); !errors.Is(err, ErrBadCredentials) {
			t.Errorf("CheckPassword(%q, %q) = %v", tc[0], tc[1], err)
		}
	}

	// Closed for good: even with no admin left, setup does not reopen.
	if _, err := s.pool.Exec(ctx, "DELETE FROM user_roles"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.SetupToken(ctx); tok != "" {
		t.Errorf("setup reopened once no admin was left")
	}
}

func TestPasswordLoginSetting(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	token, _ := s.SetupToken(ctx)
	owner, err := s.Bootstrap(ctx, token, "owner", "password1")
	if err != nil {
		t.Fatal(err)
	}
	// A User with a password but no Management API Role, to prove the setting
	// is the only thing that decides.
	hash, err := hashPassword("password2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO users (id) VALUES ('u2');
		INSERT INTO identifiers VALUES ('u2', 'username', 'user');
		INSERT INTO passwords VALUES ('u2', '`+hash+`')`); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		setting     string
		owner, user bool // can log in
	}{
		{"on", true, true}, // the default
		{"off", false, false},
	} {
		if _, err := s.pool.Exec(ctx, "UPDATE settings SET password_login = $1", tc.setting); err != nil {
			t.Fatal(err)
		}
		got, err := s.CheckPassword(ctx, "owner", "password1")
		if (got == owner) != tc.owner {
			t.Errorf("%s: owner = %q %v", tc.setting, got, err)
		}
		got, err = s.CheckPassword(ctx, "user", "password2")
		if (got == "u2") != tc.user {
			t.Errorf("%s: user = %q %v", tc.setting, got, err)
		}
	}
}

func owner(t *testing.T, s *Store) string {
	t.Helper()
	ctx := context.Background()
	token, _ := s.SetupToken(ctx)
	sub, err := s.Bootstrap(ctx, token, "owner", "password1")
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func audited(t *testing.T, s *Store, event string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE event = $1", event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFiveWrongPasswordsLockPasswordLogin(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub := owner(t, s)

	// A right password in between starts the count over.
	for range 4 {
		if _, err := s.CheckPassword(ctx, "owner", "wrong"); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if got, err := s.CheckPassword(ctx, "owner", "password1"); got != sub {
		t.Fatal(got, err)
	}
	for range 4 {
		if _, err := s.CheckPassword(ctx, "owner", "wrong"); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	// However slowly.
	if _, err := s.pool.Exec(ctx, "UPDATE login_failures SET at = at - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if audited(t, s, "login.password_locked") != 0 {
		t.Fatal("locked after 4 in a row")
	}
	if _, err := s.CheckPassword(ctx, "owner", "wrong"); !errors.Is(err, ErrPasswordLocked) {
		t.Fatalf("5th wrong password: %v", err)
	}
	if _, err := s.CheckPassword(ctx, "owner", "password1"); !errors.Is(err, ErrPasswordLocked) {
		t.Fatalf("right password while locked: %v", err)
	}
	if n := audited(t, s, "login.password_locked"); n != 1 {
		t.Errorf("audited %d lockouts", n)
	}

	// 15 minutes later.
	if _, err := s.pool.Exec(ctx, "UPDATE lockouts SET until = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CheckPassword(ctx, "owner", "password1"); got != sub {
		t.Fatalf("after the lockout: %q %v", got, err)
	}
}

func TestFiftyFailuresLockAnIPOut(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)
	wrong := func(ip string) error {
		return s.FromIP(ctx, ip, func() error { return ErrWrongCode })
	}
	for i := range 49 {
		user := []string{"owner", "nobody"}[i%2] // known or not, all count
		if err := s.FromIP(ctx, "192.0.2.1", func() error {
			_, err := s.CheckPassword(ctx, user, "wrong")
			return err
		}); !errors.Is(err, ErrBadCredentials) && !errors.Is(err, ErrPasswordLocked) {
			t.Fatal(i, err)
		}
	}
	if err := wrong("192.0.2.1"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("50th failure: %v", err)
	}
	if n := audited(t, s, "login.ip_locked"); n != 1 {
		t.Errorf("audited %d IP lockouts", n)
	}
	ran := false
	if err := s.FromIP(ctx, "192.0.2.1", func() error { ran = true; return nil }); !errors.Is(err, ErrIPLocked) || ran {
		t.Fatalf("while locked out: %v, check ran %v", err, ran)
	}
	if err := s.FromIP(ctx, "192.0.2.2", func() error { return nil }); err != nil {
		t.Fatalf("another IP: %v", err)
	}
}

func TestDisabledUserCannotSignIn(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)
	if _, err := s.SignIn(ctx, "email", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE users SET disabled_at = now()"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckPassword(ctx, "owner", "password1"); !errors.Is(err, ErrDisabled) {
		t.Errorf("password: %v", err)
	}
	if _, err := s.CheckPassword(ctx, "owner", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong password: %v", err) // being disabled tells no one the password
	}
	if _, err := s.SignIn(ctx, "email", "a@example.com"); !errors.Is(err, ErrDisabled) {
		t.Errorf("code: %v", err)
	}
}

// defaultRole makes a business API Role default, the way the Management API
// does (internal/management).
func defaultRole(t *testing.T, s *Store, key string) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `
		INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track') ON CONFLICT DO NOTHING;
		INSERT INTO roles (api, key, name, default_role) VALUES ('https://track.example', '`+key+`', '`+key+`', true)`); err != nil {
		t.Fatal(err)
	}
}

// rolesOf lists a User's Roles, whatever the API.
func rolesOf(t *testing.T, s *Store, sub string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), "SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role", sub)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestSignInGetsDefaultRoles(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	defaultRole(t, s, "member")

	sub, err := s.SignIn(ctx, "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := rolesOf(t, s, sub); !slices.Equal(got, []string{"member"}) {
		t.Errorf("a new User: %v", got)
	}
	// A User who already exists keeps what they had when another Role is
	// made default, while the next one gets both.
	defaultRole(t, s, "editor")
	if got := rolesOf(t, s, sub); !slices.Equal(got, []string{"member"}) {
		t.Errorf("an existing User after a Role is made default: %v", got)
	}
	other, err := s.SignIn(ctx, "phone", "+8613800138000")
	if err != nil {
		t.Fatal(err)
	}
	if got := rolesOf(t, s, other); !slices.Equal(got, []string{"editor", "member"}) {
		t.Errorf("the next User: %v", got)
	}
}

func TestBootstrapGetsDefaultRoles(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	defaultRole(t, s, "member")
	token, _ := s.SetupToken(ctx)
	owner, err := s.Bootstrap(ctx, token, "root", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if got := rolesOf(t, s, owner); !slices.Equal(got, []string{"member", "owner"}) {
		t.Errorf("the first owner: %v", got)
	}
}

// 管理员创建 User (ADR 0016): 建号、加标识符、设初始密码、置待激活在一个
// 事务里; 初始密码能登录, 但 User 处于待激活。
func TestCreatePendingUser(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s) // 密码登录开着, 且实例已引导

	sub, err := s.CreatePendingUser(ctx, "Alice@Example.com ", "password1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sub == "" {
		t.Fatal("no sub")
	}
	// 标识符按既有口径归一化并用它登录.
	if got, err := s.CheckPassword(ctx, "alice@example.com", "password1"); err != nil || got != sub {
		t.Errorf("sign in with the initial password: %q %v, want %q", got, err, sub)
	}
	if pending, err := s.Pending(ctx, sub); err != nil || !pending {
		t.Errorf("pending = %v %v, want true", pending, err)
	}
	// 照常拿业务 API 的默认 Role, 与其它创建途径一致 (rbac.md). 默认 Role
	// 只在创建时授予, 所以先建一条再建第二个 User 比。
	defaultRole(t, s, "member")
	withRole, err := s.CreatePendingUser(ctx, "dave@example.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if got := rolesOf(t, s, withRole); !slices.Equal(got, []string{"member"}) {
		t.Errorf("roles = %v, want [member]", got)
	}

	// 手机号与用户名同样接受; 用户名不要求 @ 或 +, 走 ParseIdentifier 会失败.
	if _, err := s.CreatePendingUser(ctx, "13800001111", "password1"); err != nil {
		t.Errorf("phone: %v", err)
	}
	if _, err := s.CreatePendingUser(ctx, "bob", "password1"); err != nil {
		t.Errorf("username: %v", err)
	}

	// 已被占用的标识符: 明确错误, 且不留下半个 User.
	before := countUsers(t, s)
	for _, id := range []string{"alice@example.com", "13800001111", "bob"} {
		if _, err := s.CreatePendingUser(ctx, id, "password1"); !errors.Is(err, ErrIdentifierTaken) {
			t.Errorf("%q: %v, want ErrIdentifierTaken", id, err)
		}
	}
	if after := countUsers(t, s); after != before {
		t.Errorf("%d Users left behind, want %d", after, before)
	}

	// 密码规则沿用现有; 标识符不认识时明确拒绝.
	if _, err := s.CreatePendingUser(ctx, "carol@example.com", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("short password: %v", err)
	}
	if _, err := s.CreatePendingUser(ctx, "not an identifier", "password1"); !errors.Is(err, ErrCreateIdentifier) {
		t.Errorf("bad identifier: %v", err)
	}
}

// 强制改密: 待激活的 User 设完自己的密码即激活; 已激活的账号再走一次这条
// 通路什么也不做 —— 否则重放一个 auth_session 就能改别人的密码。
func TestSetPasswordIfPendingActivates(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)

	sub, err := s.CreatePendingUser(ctx, "alice@example.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	changes := audited(t, s, "password.changed")
	if err := s.SetPasswordIfPending(ctx, sub, "mine-mine-mine"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if pending, _ := s.Pending(ctx, sub); pending {
		t.Error("still 待激活 after setting a password")
	}
	if _, err := s.CheckPassword(ctx, "alice@example.com", "mine-mine-mine"); err != nil {
		t.Errorf("sign in with the new password: %v", err)
	}
	if _, err := s.CheckPassword(ctx, "alice@example.com", "password1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("the initial password still works: %v", err)
	}
	if n := audited(t, s, "password.changed"); n != changes+1 {
		t.Errorf("%d password.changed events, want %d", n, changes+1)
	}

	// 已激活: 这条通路关掉了.
	if err := s.SetPasswordIfPending(ctx, sub, "someone-else"); !errors.Is(err, ErrNotPending) {
		t.Errorf("on an active User: %v, want ErrNotPending", err)
	}
	if _, err := s.CheckPassword(ctx, "alice@example.com", "mine-mine-mine"); err != nil {
		t.Errorf("the password changed anyway: %v", err)
	}
	if n := audited(t, s, "password.changed"); n != changes+1 {
		t.Errorf("%d password.changed events, want %d: an activated account was written to", n, changes+1)
	}

	// 密码规则同样适用.
	other, _ := s.CreatePendingUser(ctx, "bob@example.com", "password1")
	if err := s.SetPasswordIfPending(ctx, other, "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("short: %v", err)
	}
	if pending, _ := s.Pending(ctx, other); !pending {
		t.Error("a rejected password activated the account")
	}
}

// 禁用优先于待激活: 被禁用的 User 不能登录, 所以他不算待激活, 也不会被
// 强制改密拦住 —— 他根本进不来。
func TestDisabledBeatsPending(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)
	sub, err := s.CreatePendingUser(ctx, "alice@example.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", sub); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.Pending(ctx, sub); err != nil || pending {
		t.Errorf("a disabled User is 待激活: %v %v", pending, err)
	}
	if _, err := s.CheckPassword(ctx, "alice@example.com", "password1"); !errors.Is(err, ErrDisabled) {
		t.Errorf("sign in: %v, want ErrDisabled", err)
	}
}

func countUsers(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Logging in binds a verified Identifier to an existing User and queues
// user.updated for each Application with a webhook; signing up queues
// nothing, and a refused binding rolls its delivery back.
func TestBindingAnIdentifierAtLoginQueuesUserUpdated(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO applications (client_id, name, type, webhook_url, webhook_secret) VALUES
		    ('hooked', 'hooked', 'public', 'https://rp.example/hook', '\x00'), ('plain', 'plain', 'public', NULL, NULL)`); err != nil {
		t.Fatal(err)
	}
	queued := func() []string {
		t.Helper()
		var got []string
		if err := s.pool.QueryRow(ctx, `
			WITH d AS (DELETE FROM webhook_deliveries RETURNING client_id, payload)
			SELECT COALESCE(array_agg(d.client_id || ' ' || (d.payload->>'type') || ' ' || (d.payload->'data')::text), '{}') FROM d`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	sub, err := s.SignIn(ctx, "email", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := queued(); len(got) != 0 {
		t.Errorf("sign-up queued %v", got)
	}
	if err := s.AddIdentifier(ctx, sub, "phone", "+8613800138000"); err != nil {
		t.Fatal(err)
	}
	if got := queued(); !slices.Equal(got, []string{`hooked user.updated {"sub": "` + sub + `", "changed": ["phone"]}`}) {
		t.Errorf("binding queued %v", got)
	}
	other, _ := s.SignIn(ctx, "email", "bob@example.com")
	if err := s.AddIdentifier(ctx, other, "phone", "+8613800138000"); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("taken: %v", err)
	}
	if got := queued(); len(got) != 0 {
		t.Errorf("refused binding queued %v", got)
	}
}
