package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/profile"
	"github.com/zibyn/polaris/internal/twofactor"
)

type subPath struct {
	Sub string `path:"sub"`
}

type createUserInput struct {
	Body struct {
		Identifier string `json:"identifier" doc:"+86 phone number, email or username; stored normalised. An admin-typed phone number or email counts as verified at once: no code is sent (ADR 0016)"`
		Password   string `json:"password,omitempty" minLength:"8" doc:"The initial password the admin hands over; the User must replace it at first sign-in before they get any token. 互斥 with invite, and one of the two is required"`
		Invite     bool   `json:"invite,omitempty" doc:"Send a 注册邀请 instead of setting an initial password: the User sets their own, so the admin never knows it. 互斥 with password, and the Identifier must be an email. An invite that fails to send leaves the User made but with no usable link: re-send it from the User's page"`
	}
}

type createUserOutput struct {
	Body UserDetail
}

// createUser makes a User for an admin to hand over (ADR 0016). It starts
// 待激活: they can sign in with the initial password, but get no
// authorization code — hence no token — until they replace it, so no
// Application ever sees this state. The admin-typed Identifier is taken as
// verified, the same as GitLab's admin-created accounts and Keycloak's Email
// Verified checkbox; typed wrong, the account lands with whoever holds that
// address, which the admin checks offline.
//
// 初始密码 and 发注册邀请 are the two ways in and exclude each other: the first
// has the admin choose a password the User must replace, the second lets the
// User choose from the start. One of them has to be picked — a 待激活 account
// with neither has no way in at all but the 注销 button.
func (s *Service) createUser(ctx context.Context, in *createUserInput) (*createUserOutput, error) {
	switch {
	case in.Body.Invite && in.Body.Password != "":
		return nil, huma.Error422UnprocessableEntity("「初始密码」与「发注册邀请」只能选一个")
	case !in.Body.Invite && in.Body.Password == "":
		return nil, huma.Error422UnprocessableEntity("请二选一:给一个「初始密码」,或「发注册邀请」")
	}
	// 密码登录 is this feature's precondition: both ways end in a password the
	// User signs in with, so with the switch off neither is worth setting up.
	// The console disables the entry and says why.
	setting, err := s.q.PasswordLogin(ctx)
	if err != nil {
		return nil, err
	}
	if setting == "off" {
		return nil, huma.Error422UnprocessableEntity("密码登录已关闭,不能创建要设密码的账号")
	}
	var sub string
	if in.Body.Invite {
		sub, err = s.ids.CreateInvitedUser(ctx, in.Body.Identifier)
	} else {
		sub, err = s.ids.CreatePendingUser(ctx, in.Body.Identifier, in.Body.Password)
	}
	// ErrIdentifierTaken is itself an identity.Invalid, so it is named first:
	// a taken Identifier is a 409, not the 422 the other Invalid errors get.
	var bad identity.Invalid
	switch {
	case errors.Is(err, identity.ErrIdentifierTaken):
		return nil, huma.Error409Conflict(err.Error())
	case errors.As(err, &bad):
		return nil, huma.Error422UnprocessableEntity(bad.Error())
	case err != nil:
		return nil, err
	}
	// The generic audit only records path parameters, and this write has
	// none: audited here, with the User it made.
	detail, _ := json.Marshal(map[string]string{"by": callerSub(ctx)})
	if err := s.q.Audit(ctx, sqlc.AuditParams{Event: "user.created", Sub: pgtype.Text{String: sub, Valid: true}, Detail: detail}); err != nil {
		return nil, err
	}
	if in.Body.Invite {
		if err := s.sendInvite(ctx, sub); err != nil {
			// 邮件是外部副作用, 账号已经建好了 —— 只是手上没有能用的链接。说清
			// 楚这一点, 管理员才不会当它没建成再点一次: 那次会撞 409「已属于另
			// 一个 User」, 而真正的恢复动作是去用户页重发。
			msg, ok := errors.AsType[identity.Invalid](err)
			if !ok {
				return nil, err
			}
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"账号已经建好,只是邀请邮件没发出去(%s);去用户列表找到它,在详情页重发即可。", msg))
		}
	}
	r, err := s.q.GetUser(ctx, sub)
	if err != nil {
		return nil, err
	}
	u, err := userDetail(r)
	if err != nil {
		return nil, err
	}
	return &createUserOutput{Body: u}, nil
}

// ensureUser is the 404 for a User a path names who is not.
func (s *Service) ensureUser(ctx context.Context, sub string) error {
	_, err := s.q.GetUser(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return huma.Error404NotFound("no such User")
	}
	return err
}

// mayManage checks that the caller may act on sub: acting on an admin
// needs admin-roles:assign, as making one does.
func (s *Service) mayManage(ctx context.Context, sub string) error {
	u, err := s.q.GetUser(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return huma.Error404NotFound("no such User")
	} else if err != nil {
		return err
	}
	target, err := user(u.ID, u.CreatedAt.Time, u.DisabledAt, u.Pending, u.Identifiers, u.Roles)
	if err != nil {
		return err
	}
	for _, r := range target.Roles {
		if r.API == identity.ManagementAPI {
			return mayMakeAdmins(ctx)
		}
	}
	return nil
}

// guardOwners runs change under identity's last-usable-owner guard, turning
// its refusal into a 409.
func (s *Service) guardOwners(ctx context.Context, change func(*sqlc.Queries) error) error {
	err := s.ids.GuardOwners(ctx, change)
	if errors.Is(err, identity.ErrLastOwner) {
		return huma.Error409Conflict("不能禁用、删除或降级最后一个所有者")
	}
	return err
}

func (s *Service) disableUser(ctx context.Context, in *subPath) (*struct{}, error) {
	return nil, s.setDisabled(ctx, in.Sub, true)
}

func (s *Service) enableUser(ctx context.Context, in *subPath) (*struct{}, error) {
	return nil, s.setDisabled(ctx, in.Sub, false)
}

func (s *Service) setDisabled(ctx context.Context, sub string, disabled bool) error {
	if err := s.mayManage(ctx, sub); err != nil {
		return err
	}
	return s.guardOwners(ctx, func(q *sqlc.Queries) error {
		_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: sub, Disabled: disabled, By: callerSub(ctx)})
		return err
	})
}

// deleteUser removes the User and all their data; only audit events keep
// the sub (docs/spec/security-compliance.md#数据留存).
func (s *Service) deleteUser(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	return nil, s.providers.DeleteUser(ctx, in.Sub, func(ctx context.Context, sub string) error {
		return s.guardOwners(ctx, func(q *sqlc.Queries) error {
			if err := profile.DeleteAvatar(ctx, q, sub); err != nil {
				return err
			}
			_, err := q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: sub, By: callerSub(ctx)})
			return err
		})
	})
}

type setNicknameInput struct {
	Sub  string `path:"sub"`
	Body struct {
		Nickname string `json:"nickname" doc:"Trimmed; 1–32 characters with no control characters, or empty to clear it"`
	}
}

func (s *Service) setNickname(ctx context.Context, in *setNicknameInput) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	err := s.profiles.SetNickname(ctx, in.Sub, in.Body.Nickname, callerSub(ctx))
	var invalid profile.Invalid
	if errors.As(err, &invalid) {
		return nil, huma.Error400BadRequest(invalid.Error())
	}
	return nil, err
}

// removeAvatar takes down an avatar that breaks the rules; an admin cannot
// put one up.
func (s *Service) removeAvatar(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	return nil, s.profiles.RemoveAvatar(ctx, in.Sub, callerSub(ctx))
}

type replaceIdentifierInput struct {
	Sub  string `path:"sub"`
	Kind string `path:"kind" enum:"phone,email,username"`
	Body struct {
		Value string `json:"value" doc:"+86 phone number, email or username; normalised"`
	}
}

func (s *Service) replaceIdentifier(ctx context.Context, in *replaceIdentifierInput) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	var value string
	var err error
	if in.Kind == "username" {
		value, err = identity.CheckUsername(in.Body.Value)
	} else {
		var kind string
		kind, value, err = identity.ParseIdentifier(in.Body.Value)
		if err == nil && kind != in.Kind {
			err = identity.ErrIdentifier
		}
	}
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	err = s.ids.ReplaceIdentifier(ctx, in.Sub, in.Kind, value, callerSub(ctx))
	if errors.Is(err, identity.ErrIdentifierTaken) {
		return nil, huma.Error409Conflict(err.Error())
	}
	return nil, err
}

// resetTwoFactor is for a User who lost both their authenticator and 恢复码;
// the admin checked who they are offline.
func (s *Service) resetTwoFactor(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	err := s.twoFactor.Disable(ctx, in.Sub, "mfa.reset", callerSub(ctx))
	if errors.Is(err, twofactor.ErrOff) || errors.Is(err, twofactor.ErrNotBegun) {
		return nil, huma.Error409Conflict("该 User 未开启两步验证")
	}
	return nil, err
}

func callerSub(ctx context.Context) string { return ctx.Value(callerKey{}).(caller).sub }
