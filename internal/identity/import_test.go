package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// 导入 User (ADR 0033): 只带标识符或再加原密码哈希, 建出的是正常 User;
// bcrypt 哈希在第一次登录成功后转存为 argon2id。
func TestCreateUserImports(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	owner(t, s)
	hashOf := func(sub string) string {
		var h string
		if err := s.pool.QueryRow(ctx, "SELECT hash FROM passwords WHERE user_id = $1", sub).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}

	// 标识符而已: 正常 User, 没有密码, 凭验证码登录。
	sub, err := s.CreateUser(ctx, "Alice@Example.com", "")
	if err != nil {
		t.Fatalf("email alone: %v", err)
	}
	if pending, err := s.Pending(ctx, sub); err != nil || pending {
		t.Errorf("pending = %v %v, want false", pending, err)
	}
	if _, err := s.q.PasswordByIdentifier(ctx, "alice@example.com"); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("a password out of nowhere: %v", err)
	}
	// 用户名不带哈希没有任何登录途径。
	if _, err := s.CreateUser(ctx, "bob", ""); !errors.Is(err, ErrUsernameNeedsHash) {
		t.Errorf("username alone: %v", err)
	}

	// bcrypt, $2y$ 写法 (PHP): 能登录, 登录成功后转存为 argon2id。
	b, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	bc := "$2y$" + string(b[4:])
	sub, err = s.CreateUser(ctx, "bob", bc)
	if err != nil {
		t.Fatalf("username + bcrypt: %v", err)
	}
	if pending, _ := s.Pending(ctx, sub); pending {
		t.Error("an imported User is 待激活")
	}
	if _, err := s.CheckPassword(ctx, Attempt{}, "bob", "wrong-password"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if hashOf(sub) != bc {
		t.Error("a failed sign-in rehashed")
	}
	if got, err := s.CheckPassword(ctx, Attempt{}, "bob", "old-password"); err != nil || got != sub {
		t.Fatalf("bcrypt sign-in: %q %v", got, err)
	}
	if h := hashOf(sub); !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("not re-stored as argon2id: %q", h)
	}
	if got, err := s.CheckPassword(ctx, Attempt{}, "bob", "old-password"); err != nil || got != sub {
		t.Errorf("sign-in after the rehash: %q %v", got, err)
	}

	// argon2id 原样存下。
	a, err := hashPassword("carol-password")
	if err != nil {
		t.Fatal(err)
	}
	sub, err = s.CreateUser(ctx, "carol@example.com", a)
	if err != nil {
		t.Fatalf("argon2id: %v", err)
	}
	if got, err := s.CheckPassword(ctx, Attempt{}, "carol@example.com", "carol-password"); err != nil || got != sub {
		t.Errorf("argon2id sign-in: %q %v", got, err)
	}

	// 别的格式一律拒绝, 不留下 User。
	before := countUsers(t, s)
	for _, h := range []string{
		"plaintext",
		"$1$abc$def", // md5-crypt
		strings.Replace(a, "argon2id", "argon2i", 1),
		"$2a$04$tooshort",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdA$a2V5",   // t=0 would panic argon2
		"$argon2id$v=19$m=4194304,t=2,p=1$c2FsdA$a2V5", // 4 GiB per sign-in
		"$2b$31$" + strings.Repeat("a", 53),            // bcrypt cost 31
	} {
		if _, err := s.CreateUser(ctx, "dave@example.com", h); !errors.Is(err, ErrPasswordHash) {
			t.Errorf("%q: %v, want ErrPasswordHash", h, err)
		}
	}
	if _, err := s.CreateUser(ctx, "alice@example.com", ""); !errors.Is(err, ErrIdentifierTaken) {
		t.Errorf("taken: %v", err)
	}
	if after := countUsers(t, s); after != before {
		t.Errorf("%d Users, want %d", after, before)
	}
}
