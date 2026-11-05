package management

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/audit"
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
		Identifier   string `json:"identifier" doc:"+86 phone number, email or username; stored normalised. An admin-typed phone number or email counts as verified at once: no code is sent (ADR 0016). Already held by another User: 409, with that User's sub in the body, and nothing is written"`
		Password     string `json:"password,omitempty" minLength:"8" doc:"The initial password the admin hands over: the User is made 待激活 and must replace it at first sign-in before they get any token. 互斥 with invite and password_hash"`
		Invite       bool   `json:"invite,omitempty" doc:"Send a 注册邀请 instead of setting an initial password: the User is made 待激活 and sets their own, so the admin never knows it. 互斥 with password and password_hash, and the Identifier must be an email. An invite that fails to send leaves the User made but with no usable link: re-send it from the User's page"`
		PasswordHash string `json:"password_hash,omitempty" doc:"Import the User with the password hash they had in the 集成方's old user store (ADR 0033): argon2id in PHC string format, or bcrypt ($2a$, $2b$, $2y$); any other format is a 422. The User is made normal, not 待激活, and their first sign-in with it re-stores it as argon2id. 互斥 with password and invite. With none of the three, the User is made normal with just the Identifier and signs in by code, so a username alone is refused. password, invite and password_hash are each a 422 while 密码登录 is off; the Identifier alone is not"`
	}
}

type createUserOutput struct {
	Body UserDetail
}

// identifierTaken is the 409 for an Identifier another User holds, naming
// that User so an importing 集成方 can link to them (ADR 0033).
type identifierTaken struct {
	huma.ErrorModel
	Sub string `json:"sub" doc:"The User who holds the Identifier"`
}

// createUser makes a User (ADR 0016, 0033), in one of three ways:
//
//   - 初始密码 or 发注册邀请 make a User for an admin to hand over. It starts
//     待激活: they can sign in, but get no authorization code — hence no
//     token — until they set a password of their own, so no Application ever
//     sees this state. Both end in a password, so 密码登录 must be on.
//   - The Identifier alone, or with an imported password hash, makes a
//     normal User: an Application bringing its existing users over.
//
// The admin-typed Identifier is taken as verified either way, the same as
// GitLab's admin-created accounts and Keycloak's Email Verified checkbox;
// typed wrong, the account lands with whoever holds that address, which the
// caller checks offline.
func (s *Service) createUser(ctx context.Context, in *createUserInput) (*createUserOutput, error) {
	b := &in.Body
	ways := 0
	for _, set := range []bool{b.Password != "", b.Invite, b.PasswordHash != ""} {
		if set {
			ways++
		}
	}
	if ways > 1 {
		return nil, huma.Error422UnprocessableEntity("「初始密码」「发注册邀请」「密码哈希」只能选一个")
	}
	if ways == 1 {
		// The console disables the entry and says why.
		setting, err := s.q.PasswordLogin(ctx)
		if err != nil {
			return nil, err
		}
		if setting == "off" {
			return nil, huma.Error422UnprocessableEntity("密码登录已关闭,不能创建要设密码的账号")
		}
	}
	var sub string
	var err error
	switch {
	case b.Invite:
		sub, err = s.ids.CreateInvitedUser(ctx, b.Identifier)
	case b.Password != "":
		sub, err = s.ids.CreatePendingUser(ctx, b.Identifier, b.Password)
	default:
		sub, err = s.ids.CreateUser(ctx, b.Identifier, b.PasswordHash)
	}
	// ErrIdentifierTaken is itself an identity.Invalid, so it is named first:
	// a taken Identifier is a 409, not the 422 the other Invalid errors get.
	var bad identity.Invalid
	switch {
	case errors.Is(err, identity.ErrIdentifierTaken):
		return nil, s.identifierTaken(ctx, b.Identifier, err)
	case errors.As(err, &bad):
		return nil, huma.Error422UnprocessableEntity(bad.Error())
	case err != nil:
		return nil, err
	}
	// The generic audit only records path parameters, and this write has
	// none: audited here, with the User it made.
	detail := callerActor(ctx).Detail(nil)
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

func (s *Service) identifierTaken(ctx context.Context, identifier string, taken error) error {
	_, value, err := identity.ParseCreateIdentifier(identifier)
	if err != nil {
		return err
	}
	u, err := s.q.UserByIdentifier(ctx, value)
	if errors.Is(err, pgx.ErrNoRows) { // the holder went away since
		return huma.Error409Conflict(taken.Error())
	} else if err != nil {
		return err
	}
	return &identifierTaken{huma.ErrorModel{Title: "Conflict", Status: http.StatusConflict, Detail: taken.Error()}, u.UserID}
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

// ownerErr turns identity's last-usable-owner refusal into a 409.
func ownerErr(err error) error {
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
	return ownerErr(s.ids.SetDisabled(ctx, sub, disabled, callerActor(ctx)))
}

// deleteUser removes the User and all their data; only audit events keep
// the sub (docs/spec/security-compliance.md#数据留存).
func (s *Service) deleteUser(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	return nil, s.providers.DeleteUser(ctx, in.Sub, func(ctx context.Context, sub string) error {
		return ownerErr(s.ids.Delete(ctx, sub, callerActor(ctx)))
	})
}

type setProfileInput struct {
	Sub  string `path:"sub"`
	Body profile.Patch
}

func (s *Service) setProfile(ctx context.Context, in *setProfileInput) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	err := s.profiles.Update(ctx, in.Sub, in.Body, callerActor(ctx))
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
	return nil, s.profiles.RemoveAvatar(ctx, in.Sub, callerActor(ctx))
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
	err = s.ids.ReplaceIdentifier(ctx, in.Sub, in.Kind, value, callerActor(ctx))
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
	err := s.twoFactor.Disable(ctx, in.Sub, "mfa.reset", callerActor(ctx))
	if errors.Is(err, twofactor.ErrOff) || errors.Is(err, twofactor.ErrNotBegun) {
		return nil, huma.Error409Conflict("该 User 未开启两步验证")
	}
	return nil, err
}

// callerActor is who an audited change is by: the caller, a User or an M2M
// Application calling as itself.
func callerActor(ctx context.Context) audit.Actor {
	c := ctx.Value(callerKey{}).(caller)
	if c.application {
		return audit.Application(c.sub)
	}
	return audit.User(c.sub)
}
