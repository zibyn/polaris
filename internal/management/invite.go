package management

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// errPasswordOff is the same precondition setting 初始密码 has: both end in a
// password the User signs in with, which an instance that turned 密码登录 off
// does not take.
var errPasswordOff = huma.Error422UnprocessableEntity("密码登录已关闭,不能邀请别人设密码")

// invite reads a User's 注册邀请 out of their row. A link still on file is
// 已发出, and its expiry is the one the link itself has. One the User has
// spent is 已接受 — accepting deletes the row, so the audit log is the only
// place that still says so. Everything else (never sent, revoked, expired) is
// 没发出: there is no link anybody can use.
func invite(r sqlc.GetUserRow) Invite {
	if r.InviteExpiresAt.Valid {
		at := r.InviteExpiresAt.Time
		return Invite{State: "sent", ExpiresAt: &at}
	}
	if r.InviteEvent == "invite.accepted" {
		return Invite{State: "accepted"}
	}
	return Invite{State: "none"}
}

// sendInvite mints a 注册邀请 for sub and mails it. users:write and mayManage
// are the caller's business; this is the part both endpoints share.
//
// It returns the error unmapped so a caller can say more about it: creating a
// User and inviting an existing one differ in what a failure leaves behind.
//
// 重发走的是同一个入口: MintInvite 替换掉 sub 原有的 token, 所以旧链接在
// 新邮件发出的那一刻失效。
//
// 发信失败不留可用 token: 刚铸出来的那条随即删掉。账号本身留着 —— 邮件是外部
// 副作用, 把账号回滚掉只会让"邮件到了但人不存在"。
func (s *Service) sendInvite(ctx context.Context, sub string) error {
	token, email, err := s.ids.MintInvite(ctx, sub)
	if err != nil {
		return err
	}
	if err := s.codes.SendInvite(ctx, email, s.issuer+"/invite?token="+token); err != nil {
		// 不是一次撤销: 没有人收到过链接, 也就不该有 invite.revoked。
		if dropErr := s.ids.DropInvite(ctx, sub); dropErr != nil {
			slog.Error("drop invite", "sub", sub, "err", dropErr)
		}
		return err
	}
	detail, _ := json.Marshal(map[string]string{"by": callerSub(ctx)})
	return s.q.Audit(ctx, sqlc.AuditParams{Event: "invite.sent", Sub: pgtype.Text{String: sub, Valid: true}, Detail: detail})
}

// inviteUser sends — or re-sends — a User's 注册邀请.
func (s *Service) inviteUser(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	if setting, err := s.q.PasswordLogin(ctx); err != nil {
		return nil, err
	} else if setting == "off" {
		return nil, errPasswordOff
	}
	if err := s.sendInvite(ctx, in.Sub); err != nil {
		return nil, invalid(err)
	}
	return nil, nil
}

// revokeInvite takes a User's invite back: the link stops working that instant,
// because revoking is deleting the row the link's hash names. Revoking one that
// is not there is not an error — the caller wanted no usable link, and there is
// none — and it is not an audit event either.
func (s *Service) revokeInvite(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	_, err := s.ids.RevokeInvite(ctx, in.Sub, callerSub(ctx))
	return nil, err
}
