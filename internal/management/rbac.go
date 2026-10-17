package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
	"github.com/zibyn/stars-auth/internal/identity"
)

type setUserRolesInput struct {
	Sub  string `path:"sub"`
	Body struct {
		API   string   `json:"api" doc:"Identifier of the API"`
		Roles []string `json:"roles" nullable:"false" doc:"Keys of every Role the User should hold on the API; Roles left out are taken away"`
	}
}

func (s *Service) setUserRoles(ctx context.Context, in *setUserRolesInput) (*struct{}, error) {
	c := ctx.Value(callerKey{}).(caller)
	admin := in.Body.API == identity.ManagementAPI
	if admin {
		if err := mayMakeAdmins(ctx); err != nil {
			return nil, err
		}
	} else if _, err := s.q.APIBuiltin(ctx, in.Body.API); errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error404NotFound("no such API")
	} else if err != nil {
		return nil, err
	}
	if err := s.ensureUser(ctx, in.Sub); err != nil {
		return nil, err
	}
	change := func(q *sqlc.Queries) error {
		err := q.SetUserRoles(ctx, sqlc.SetUserRolesParams{UserID: in.Sub, Api: in.Body.API, Roles: in.Body.Roles, By: c.sub})
		if isFKViolation(err) {
			return huma.Error422UnprocessableEntity("没有这个 Role")
		}
		return err
	}
	if admin {
		return nil, s.guardOwners(ctx, change)
	}
	return nil, change(s.q)
}

// API is an API as the console's 接入 group shows it.
type API struct {
	Identifier  string           `json:"identifier" doc:"What access tokens for it carry as aud"`
	Name        string           `json:"name"`
	Builtin     bool             `json:"builtin" doc:"The Management API: its built-in Roles and Permissions cannot be changed"`
	Permissions []PermissionInfo `json:"permissions" nullable:"false"`
	Roles       []RoleDef        `json:"roles" nullable:"false"`
}

type PermissionInfo struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Builtin bool   `json:"builtin"`
}

type RoleDef struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Builtin      bool     `json:"builtin"`
	Default      bool     `json:"default" doc:"Assigned to every User created after this; business APIs only"`
	Permissions  []string `json:"permissions" nullable:"false" doc:"Keys of its Permissions"`
	Users        int      `json:"users" doc:"How many Users hold it"`
	Applications int      `json:"applications" doc:"How many M2M Applications hold it"`
}

type listAPIsOutput struct {
	Body struct {
		APIs []API `json:"apis" nullable:"false"`
	}
}

func (s *Service) listAPIs(ctx context.Context, _ *struct{}) (*listAPIsOutput, error) {
	rows, err := s.q.ListAPIs(ctx)
	if err != nil {
		return nil, err
	}
	out := &listAPIsOutput{}
	out.Body.APIs = []API{}
	for _, r := range rows {
		a := API{Identifier: r.Identifier, Name: r.Name, Builtin: r.Builtin}
		if err := json.Unmarshal(r.Permissions, &a.Permissions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(r.Roles, &a.Roles); err != nil {
			return nil, err
		}
		out.Body.APIs = append(out.Body.APIs, a)
	}
	return out, nil
}

type APIPath struct {
	API string `path:"api" maxLength:"200" pattern:"^\\S+$" doc:"API identifier, URL-escaped"`
}

// KeyPath names a Permission or Role. Keys never change once defined; names
// are free text.
type KeyPath struct {
	API string `path:"api"`
	Key string `path:"key" pattern:"^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$"`
}

type nameBody struct {
	Name string `json:"name" minLength:"1" maxLength:"64"`
}

var errBuiltin = huma.Error409Conflict("内置的 API、Role 和 Permission 不能修改或删除")

// editable checks that the caller may change what is defined on an API: 404
// when it does not exist. The Management API's own definitions are fixed;
// its custom Roles are open only to those who may make admins, or
// applications:write would be a way to hand out any Management API
// Permission.
func (s *Service) editable(ctx context.Context, api string, roles bool) error {
	b, err := s.q.APIBuiltin(ctx, api)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return huma.Error404NotFound("no such API")
	case err != nil || !b:
		return err
	case !roles:
		return errBuiltin
	}
	return mayMakeAdmins(ctx)
}

func mayMakeAdmins(ctx context.Context) error {
	if !slices.Contains(ctx.Value(callerKey{}).(caller).permissions, "admin-roles:assign") {
		return huma.Error403Forbidden("missing permission admin-roles:assign")
	}
	return nil
}

type ForceQuery struct {
	Force bool `query:"force" doc:"Confirms deleting it while Users hold its Roles, taking them away"`
}

func (s *Service) putAPI(ctx context.Context, in *struct {
	APIPath
	Body nameBody
}) (*struct{}, error) {
	if n, err := s.q.PutAPI(ctx, sqlc.PutAPIParams{Identifier: in.API, Name: in.Body.Name}); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, errBuiltin
	}
	return nil, nil
}

func (s *Service) deleteAPI(ctx context.Context, in *struct {
	APIPath
	ForceQuery
}) (*struct{}, error) {
	if err := s.editable(ctx, in.API, false); err != nil {
		return nil, err
	}
	n, err := s.q.DeleteAPI(ctx, sqlc.DeleteAPIParams{Identifier: in.API, Force: in.Force})
	switch {
	case isFKViolation(err):
		return nil, huma.Error409Conflict("还有 Application 以它为默认 API")
	case err != nil:
		return nil, err
	case n == 0:
		return nil, huma.Error409Conflict("它的 Role 仍分配给 User;确认后连同分配一起删除")
	}
	return nil, nil
}

func (s *Service) putPermission(ctx context.Context, in *struct {
	KeyPath
	Body nameBody
}) (*struct{}, error) {
	if err := s.editable(ctx, in.API, false); err != nil {
		return nil, err
	}
	return nil, s.q.PutPermission(ctx, sqlc.PutPermissionParams{Api: in.API, Key: in.Key, Name: in.Body.Name})
}

func (s *Service) deletePermission(ctx context.Context, in *KeyPath) (*struct{}, error) {
	if err := s.editable(ctx, in.API, false); err != nil {
		return nil, err
	}
	if n, err := s.q.DeletePermission(ctx, sqlc.DeletePermissionParams{Api: in.API, Key: in.Key}); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, huma.Error404NotFound("no such Permission")
	}
	return nil, nil
}

type putRoleInput struct {
	KeyPath
	Body struct {
		Name        string   `json:"name" minLength:"1" maxLength:"64"`
		Permissions []string `json:"permissions" nullable:"false" doc:"Keys of the Permissions it grants, on the same API"`
		Default     bool     `json:"default,omitempty" doc:"Give it to every User created after this; business APIs only"`
	}
}

func (s *Service) putRole(ctx context.Context, in *putRoleInput) (*struct{}, error) {
	if err := s.editable(ctx, in.API, true); err != nil {
		return nil, err
	}
	// A default Role is handed to every new User, so the Management API may
	// never have one: nobody signs up as an admin.
	if in.Body.Default {
		if builtin, err := s.q.APIBuiltin(ctx, in.API); err != nil {
			return nil, err
		} else if builtin {
			return nil, huma.Error422UnprocessableEntity("内置 API 不能设置默认 Role")
		}
	}
	return nil, pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.PutRole(ctx, sqlc.PutRoleParams{Api: in.API, Key: in.Key, Name: in.Body.Name, DefaultRole: in.Body.Default}); err != nil {
			return err
		} else if n == 0 {
			return errBuiltin
		}
		err := q.SetRolePermissions(ctx, sqlc.SetRolePermissionsParams{Api: in.API, Role: in.Key, Permissions: in.Body.Permissions})
		if isFKViolation(err) {
			return huma.Error422UnprocessableEntity("没有这个 Permission")
		}
		return err
	})
}

func (s *Service) deleteRole(ctx context.Context, in *struct {
	KeyPath
	ForceQuery
}) (*struct{}, error) {
	if err := s.editable(ctx, in.API, true); err != nil {
		return nil, err
	}
	r, err := s.q.RoleUsers(ctx, sqlc.RoleUsersParams{Api: in.API, Key: in.Key})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error404NotFound("no such Role")
	} else if err != nil {
		return nil, err
	}
	if r.Builtin {
		return nil, errBuiltin
	}
	if n, err := s.q.DeleteRole(ctx, sqlc.DeleteRoleParams{Api: in.API, Key: in.Key, Force: in.Force}); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, huma.Error409Conflict(heldBy(r.Users, r.Applications) + ";确认后连同分配一起删除")
	}
	return nil, nil
}

// heldBy says who still holds a Role, for the 409 that asks to confirm.
func heldBy(users, applications int64) string {
	var who []string
	if users > 0 {
		who = append(who, fmt.Sprintf("%d 个 User", users))
	}
	if applications > 0 {
		who = append(who, fmt.Sprintf("%d 个 Application", applications))
	}
	return strings.Join(who, "、") + " 仍持有它"
}

func isFKViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
