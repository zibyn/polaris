package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// 邀请: 发出来的是一条一次性链接, 表里只有它的 SHA-256; 接受即写密码、
// 待激活的随即激活; 重发替换旧链接; 撤销与过期都立即失效 (ADR 0016)。
func TestInviteMintsAcceptsAndReplaces(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	sub, err := s.CreateInvitedUser(ctx, "Alice@Example.com")
	if err != nil {
		t.Fatalf("create invited User: %q %v", sub, err)
	}
	// 只有邮箱, 没有任何凭据 —— 邀请链接是唯一的入口。
	if _, err := s.q.PasswordByIdentifier(ctx, "alice@example.com"); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("a fresh invited User has a password: %v", err)
	}
	if pending, err := s.Pending(ctx, sub); err != nil || !pending {
		t.Fatalf("want 待激活: %v %v", pending, err)
	}

	token, to, err := s.MintInvite(ctx, sub)
	if err != nil || token == "" || to != "alice@example.com" {
		t.Fatalf("mint: %q %q %v", token, to, err)
	}
	// 表里存的不是明文。
	var stored []byte
	if err := s.pool.QueryRow(ctx, "SELECT token_hash FROM invites WHERE user_id = $1", sub).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == token {
		t.Error("the plaintext token is in the table")
	}
	if live, err := s.InviteLive(ctx, token); err != nil || !live {
		t.Fatalf("a fresh invite is not live: %v %v", live, err)
	}

	// 重发替换: 旧链接当场作废, 表里仍然只有一行。
	second, _, err := s.MintInvite(ctx, sub)
	if err != nil || second == token {
		t.Fatalf("re-mint: %q %v", second, err)
	}
	if live, _ := s.InviteLive(ctx, token); live {
		t.Error("the replaced link still works")
	}
	var rows int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM invites WHERE user_id = $1", sub).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("invites rows = %d, want 1 (%v)", rows, err)
	}

	got, err := s.AcceptInvite(ctx, second, "her-own-password")
	if err != nil || got != sub {
		t.Fatalf("accept: %q %v", got, err)
	}
	if pending, err := s.Pending(ctx, sub); err != nil || pending {
		t.Errorf("still 待激活 after accepting: %v %v", pending, err)
	}
	if who, err := s.CheckPassword(ctx, "alice@example.com", "her-own-password"); err != nil || who != sub {
		t.Errorf("the password she set does not work: %q %v", who, err)
	}
	// 审计里「接受」的操作人是本人, 不是发邀请的管理员。
	var by string
	if err := s.pool.QueryRow(ctx, "SELECT detail->>'by' FROM audit_log WHERE event = 'invite.accepted' AND sub = $1", sub).Scan(&by); err != nil || by != sub {
		t.Errorf("invite.accepted 的操作人该是本人: %q %v", by, err)
	}
	// 一次性: 再点一次没得可花。
	if _, err := s.AcceptInvite(ctx, second, "another-password"); !errors.Is(err, ErrInviteSpent) {
		t.Errorf("a spent link: %v, want ErrInviteSpent", err)
	}
	// 而且没把密码改成第二次给的那个。
	if who, err := s.CheckPassword(ctx, "alice@example.com", "her-own-password"); err != nil || who != sub {
		t.Errorf("the second accept wrote a password: %q %v", who, err)
	}
}

// 接受也走得通已经激活的 User: 对忘了密码的人, 邀请是回得来的那条路。
func TestInviteAcceptsForAnActiveUser(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	sub, err := s.CreatePendingUser(ctx, "bob@example.com", "initial-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "no-such-token", "her-own-password"); !errors.Is(err, ErrInviteSpent) {
		t.Fatalf("no such token: %v", err)
	}
	token, _, err := s.MintInvite(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, token, "forgotten-and-new"); err != nil {
		t.Fatal(err)
	}
	if who, err := s.CheckPassword(ctx, "bob@example.com", "forgotten-and-new"); err != nil || who != sub {
		t.Errorf("the new password does not work: %q %v", who, err)
	}
}

func TestInviteExpiresAndRevokes(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub, err := s.CreateInvitedUser(ctx, "carol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.MintInvite(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE invites SET expires_at = now() - interval '1 second' WHERE user_id = $1", sub); err != nil {
		t.Fatal(err)
	}
	if live, _ := s.InviteLive(ctx, token); live {
		t.Error("an expired invite is live")
	}
	if _, err := s.AcceptInvite(ctx, token, "her-own-password"); !errors.Is(err, ErrInviteSpent) {
		t.Errorf("accepting an expired invite: %v, want ErrInviteSpent", err)
	}
	// 撤销也是删: 链接立刻不可用, 而且只有真的撤掉了一条才算一次撤销。
	second, _, _ := s.MintInvite(ctx, sub)
	if ok, err := s.RevokeInvite(ctx, sub, "ADMIN"); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if live, _ := s.InviteLive(ctx, second); live {
		t.Error("a revoked invite is still live")
	}
	if _, err := s.AcceptInvite(ctx, second, "her-own-password"); !errors.Is(err, ErrInviteSpent) {
		t.Errorf("accepting a revoked invite: %v, want ErrInviteSpent", err)
	}
	if ok, err := s.RevokeInvite(ctx, sub, "ADMIN"); err != nil || ok {
		t.Errorf("revoking nothing = %v %v, want false", ok, err)
	}
}

// 密码太短照旧按现有规则拒绝, 而且不花掉链接。
func TestInviteRejectsAShortPasswordWithoutSpendingTheLink(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub, _ := s.CreateInvitedUser(ctx, "dave@example.com")
	token, _, _ := s.MintInvite(ctx, sub)
	if _, err := s.AcceptInvite(ctx, token, "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password: %v", err)
	}
	if live, _ := s.InviteLive(ctx, token); !live {
		t.Error("a rejected password spent the link")
	}
}

// 只支持邮箱: 给没有邮箱的账号(或拿手机号建账号)发邀请一律拒绝并说明原因。
func TestInviteIsEmailOnly(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	if _, err := s.CreateInvitedUser(ctx, "+8613800001111"); !errors.Is(err, ErrInviteNeedsEmail) {
		t.Errorf("inviting a phone number: %v, want ErrInviteNeedsEmail", err)
	}
	sub, err := s.CreatePendingUser(ctx, "erin", "initial-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintInvite(ctx, sub); !errors.Is(err, ErrNoEmail) {
		t.Errorf("a User with no email: %v, want ErrNoEmail", err)
	}
}

// 被禁用的账号不接受邀请: 链接留着不花, 也不写密码 —— 管理员放开之后再点
// 那一条, 仍然作数。
func TestInviteRefusesADisabledUserWithoutSpendingIt(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub, _ := s.CreateInvitedUser(ctx, "frank@example.com")
	token, _, _ := s.MintInvite(ctx, sub)
	if _, err := s.pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", sub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, token, "her-own-password"); !errors.Is(err, ErrInviteSpent) {
		t.Fatalf("accepting for a disabled User: %v, want ErrInviteSpent", err)
	}
	if live, _ := s.InviteLive(ctx, token); !live {
		t.Error("a refused accept spent the link")
	}
	if _, err := s.q.PasswordByIdentifier(ctx, "frank@example.com"); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("a disabled User got a password: %v", err)
	}
}

// DeleteExpiredInvites 是每小时清理跑的那一个。
func TestDeleteExpiredInvitesDropsOnlyTheOldOnes(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	old, _ := s.CreateInvitedUser(ctx, "old@example.com")
	fresh, _ := s.CreateInvitedUser(ctx, "fresh@example.com")
	oldToken, _, _ := s.MintInvite(ctx, old)
	freshToken, _, _ := s.MintInvite(ctx, fresh)
	if _, err := s.pool.Exec(ctx, "UPDATE invites SET expires_at = now() - interval '1 second' WHERE user_id = $1", old); err != nil {
		t.Fatal(err)
	}
	if err := DeleteExpiredInvites(ctx, s.pool); err != nil {
		t.Fatal(err)
	}
	if live, _ := s.InviteLive(ctx, oldToken); live {
		t.Error("an expired invite survived the cleanup")
	}
	if live, _ := s.InviteLive(ctx, freshToken); !live {
		t.Error("the cleanup took a live invite")
	}
}
