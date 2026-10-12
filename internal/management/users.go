package management

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
	"github.com/zibyn/stars-auth/internal/identity"
	"github.com/zibyn/stars-auth/internal/twofactor"
)

type subPath struct {
	Sub string `path:"sub"`
}

type createUserInput struct {
	Body struct {
		Identifier string `json:"identifier" doc:"+86 phone number, email or username; stored normalised. An admin-typed phone number or email counts as verified at once: no code is sent (ADR 0016)"`
		Password   string `json:"password" minLength:"8" doc:"The initial password the admin hands over; the User must replace it at first sign-in before they get any token"`
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
func (s *Service) createUser(ctx context.Context, in *createUserInput) (*createUserOutput, error) {
	// 密码登录 is this feature's precondition: the initial password goes
	// through it, so with the switch off pre-setting one is meaningless.
	// The console disables the entry and says why.
	setting, err := s.q.PasswordLogin(ctx)
	if err != nil {
		return nil, err
	}
	if setting == "off" {
		return nil, huma.Error422UnprocessableEntity("密码登录已关闭,不能设置初始密码")
	}
	sub, err := s.ids.CreatePendingUser(ctx, in.Body.Identifier, in.Body.Password)
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
	r, err := s.q.GetUser(ctx, sub)
	if err != nil {
		return nil, err
	}
	u, err := user(r.ID, r.CreatedAt.Time, r.DisabledAt, r.Status, r.Identifiers, r.Roles)
	if err != nil {
		return nil, err
	}
	return &createUserOutput{Body: UserDetail{User: u, HasPassword: r.HasPassword, TwoFactor: r.TwoFactor, TwoFactorOrPasskey: r.TwoFactorOrPasskey}}, nil
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
	target, err := user(u.ID, u.CreatedAt.Time, u.DisabledAt, u.Status, u.Identifiers, u.Roles)
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

// ownersGuard runs change in a transaction that fails with 409 if it leaves
// no enabled owner.
func (s *Service) ownersGuard(ctx context.Context, change func(*sqlc.Queries) (int64, error)) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.LockOwners(ctx); err != nil {
			return err
		}
		if _, err := change(q); err != nil {
			return err
		}
		if n, err := q.CountOwners(ctx); err != nil {
			return err
		} else if n == 0 {
			return huma.Error409Conflict("不能禁用或删除最后一个所有者")
		}
		return nil
	})
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
	return s.ownersGuard(ctx, func(q *sqlc.Queries) (int64, error) {
		return q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: sub, Disabled: disabled, By: callerSub(ctx)})
	})
}

// deleteUser removes the User and all their data; only audit events keep
// the sub (docs/spec/security-compliance.md#数据留存).
func (s *Service) deleteUser(ctx context.Context, in *subPath) (*struct{}, error) {
	if err := s.mayManage(ctx, in.Sub); err != nil {
		return nil, err
	}
	return nil, s.providers.DeleteUser(ctx, in.Sub, func(ctx context.Context, sub string) error {
		return s.ownersGuard(ctx, func(q *sqlc.Queries) (int64, error) {
			return q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: sub, By: callerSub(ctx)})
		})
	})
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
	_, err = s.q.ReplaceIdentifier(ctx, sqlc.ReplaceIdentifierParams{UserID: in.Sub, Kind: in.Kind, Value: value, By: callerSub(ctx)})
	if isUniqueViolation(err) {
		return nil, huma.Error409Conflict(identity.ErrIdentifierTaken.Error())
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
