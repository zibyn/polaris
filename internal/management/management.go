// Package management serves the Management API: REST endpoints for admins,
// authorized live against the caller's Roles on every request.
package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/otp"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/profile"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/twofactor"
)

// Prefix is where the Management API lives; its OpenAPI document is at
// Prefix + "/openapi.json".
const Prefix = "/v1/management"

type Service struct {
	issuer    string
	pool      *pgxpool.Pool
	keyring   *crypt.Keyring
	q         *sqlc.Queries
	keys      *oidcstore.Keys
	channels  *channel.Store
	twoFactor *twofactor.Store
	providers *provider.Store
	passkeys  *passkey.Store
	ids       *identity.Store
	codes     *otp.Service
	profiles  *profile.Store
}

func New(pool *pgxpool.Pool, keyring *crypt.Keyring, issuer string) (*Service, error) {
	passkeys, err := passkey.New(pool, issuer)
	if err != nil {
		return nil, err
	}
	channels := channel.NewStore(pool, keyring)
	return &Service{issuer: issuer, pool: pool, keyring: keyring, q: sqlc.New(pool), keys: oidcstore.NewKeys(pool, keyring), channels: channels, twoFactor: twofactor.New(pool, keyring), providers: provider.NewStore(pool, keyring), passkeys: passkeys, ids: identity.New(pool, keyring), codes: otp.New(pool, channels), profiles: profile.New(pool, issuer)}, nil
}

type callerKey struct{}

// caller is who a request comes from and what they may do, read fresh from
// PG for this request.
type caller struct {
	sub         string
	permissions []string
	satisfied   bool // 两步验证或 Passkey 已满足
	totp        bool // a confirmed TOTP, whether or not a Passkey also does
	application bool // an M2M Application calling as itself, not a User
}

// TwoFactorRequired is the code of the 403 an admin without 两步验证 or a
// Passkey gets while 管理员必须启用两步验证或 Passkey is on.
const TwoFactorRequired = "two_factor_required"

// Register adds the Management API and its OpenAPI document to mux.
func (s *Service) Register(mux *http.ServeMux) {
	s.registerAssociation(mux)
	cfg := huma.DefaultConfig("Polaris Management API", "1")
	cfg.DocsPath = ""
	cfg.SchemasPath = ""
	cfg.CreateHooks = nil // no $schema links in bodies
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {Type: "http", Scheme: "bearer", BearerFormat: "JWT",
			Description: "Access token whose aud is " + identity.ManagementAPI},
	}
	cfg.Security = []map[string][]string{{"bearer": {}}}
	api := humago.NewWithPrefix(mux, Prefix, cfg)
	api.UseMiddleware(s.authorize(api))

	get(api, "me", "", "/me", "The caller and their Permissions", s.me)
	get(api, "list-users", "users:read", "/users", "Search Users", s.listUsers)
	op(api, http.MethodPost, "create-user", "users:write", "/users", "Create a User for an admin to hand over: 待激活 until they set their own password", s.createUser)
	get(api, "get-user", "users:read", "/users/{sub}", "A User's details", s.getUser)
	// 注册邀请: one admin-sent link that sets the User's own password. A send
	// that fails leaves the User made but with no usable link.
	op(api, http.MethodPost, "send-invite", "users:write", "/users/{sub}/invite", "Send or re-send a User's 注册邀请: the old link stops working at once", s.inviteUser)
	op(api, http.MethodDelete, "revoke-invite", "users:write", "/users/{sub}/invite", "Take a User's 注册邀请 back: the link stops working at once", s.revokeInvite)
	// Role names show in the Users list, so reading them needs no more than users:read.
	get(api, "list-sessions", "users:read", "/users/{sub}/sessions", "A User's Sessions", s.listSessions)
	op(api, http.MethodDelete, "end-session", "users:write", "/users/{sub}/sessions/{id}", "Sign a User out of one Session", s.endSession)
	// Acting on an admin further needs admin-roles:assign.
	op(api, http.MethodPost, "disable-user", "users:write", "/users/{sub}/disable", "Disable a User: no logins, every Session ended", s.disableUser, http.StatusConflict)
	op(api, http.MethodPost, "enable-user", "users:write", "/users/{sub}/enable", "Restore a disabled User", s.enableUser, http.StatusConflict)
	op(api, http.MethodDelete, "delete-user", "users:write", "/users/{sub}", "Delete a User and all their data", s.deleteUser, http.StatusConflict)
	op(api, http.MethodDelete, "reset-two-factor", "users:write", "/users/{sub}/2fa", "Reset a User's 两步验证: their TOTP and 恢复码 go, their Sessions stay", s.resetTwoFactor, http.StatusConflict)
	op(api, http.MethodPut, "replace-identifier", "users:write", "/users/{sub}/identifiers/{kind}", "Set a User's Identifier of a kind, replacing theirs", s.replaceIdentifier, http.StatusConflict)
	// 用户资料: an admin edits the nickname and can only take an avatar down, never upload one.
	op(api, http.MethodPatch, "set-user-nickname", "users:write", "/users/{sub}/profile", "Set or clear a User's nickname; 400 for one refused", s.setNickname, http.StatusBadRequest)
	op(api, http.MethodDelete, "remove-user-avatar", "users:write", "/users/{sub}/avatar", "Take a User's avatar down", s.removeAvatar)
	get(api, "list-user-passkeys", "users:read", "/users/{sub}/passkeys", "A User's Passkeys", s.listPasskeys)
	op(api, http.MethodDelete, "remove-user-passkey", "users:write", "/users/{sub}/passkeys/{id}", "Delete one of a User's Passkeys; its audit names the admin, not the User", s.removePasskey)
	get(api, "list-external-identities", "users:read", "/users/{sub}/external-identities", "A User's External Identities", s.listExternalIdentities)
	op(api, http.MethodDelete, "unbind-external-identity", "users:write", "/users/{sub}/external-identities/{provider}", "Unbind a User's External Identity, unless it is their last way to sign in; its Provider is told to revoke", s.unbindExternalIdentity, http.StatusConflict)
	get(api, "overview", "users:read", "/overview", "Counts for the console's overview", s.overview)
	get(api, "list-audit", "audit:read", "/audit", "Search the audit log", s.listAudit)
	get(api, "list-roles", "users:read", "/roles", "All Roles, for the Role filter", s.listRoles)
	// Management API Roles further need admin-roles:assign.
	get(api, "list-apis", "applications:read", "/apis", "APIs with their Permissions and Roles", s.listAPIs)
	op(api, http.MethodPut, "put-api", "applications:write", "/apis/{api}", "Register an API or rename it", s.putAPI, http.StatusConflict)
	op(api, http.MethodDelete, "delete-api", "applications:write", "/apis/{api}", "Delete an API with its Permissions and Roles", s.deleteAPI, http.StatusConflict)
	op(api, http.MethodPut, "put-permission", "applications:write", "/apis/{api}/permissions/{key}", "Define a Permission or rename it", s.putPermission, http.StatusConflict)
	op(api, http.MethodDelete, "delete-permission", "applications:write", "/apis/{api}/permissions/{key}", "Delete a Permission; Roles lose it too", s.deletePermission, http.StatusConflict)
	op(api, http.MethodPut, "put-role", "applications:write", "/apis/{api}/roles/{key}", "Define a Role or change its name and Permissions", s.putRole, http.StatusConflict)
	op(api, http.MethodDelete, "delete-role", "applications:write", "/apis/{api}/roles/{key}", "Delete a Role", s.deleteRole, http.StatusConflict)
	get(api, "list-applications", "applications:read", "/applications", "All Applications", s.listApplications)
	get(api, "get-application", "applications:read", "/applications/{clientId}", "An Application", s.getApplication)
	op(api, http.MethodPost, "create-application", "applications:write", "/applications", "Register an Application", s.createApplication)
	op(api, http.MethodPut, "update-application", "applications:write", "/applications/{clientId}", "Change an Application's settings", s.updateApplication, http.StatusConflict)
	op(api, http.MethodDelete, "delete-application", "applications:write", "/applications/{clientId}", "Delete an Application", s.deleteApplication, http.StatusConflict)
	op(api, http.MethodPost, "new-application-secret", "applications:write", "/applications/{clientId}/secret", "Replace a confidential Application's client secret", s.newSecret, http.StatusConflict)
	op(api, http.MethodPut, "set-user-roles", "roles:assign", "/users/{sub}/roles", "Set a User's Roles on one API", s.setUserRoles, http.StatusConflict)

	get(api, "list-application-roles", "applications:read", "/applications/{clientId}/roles", "The Roles an M2M Application holds on its API", s.listApplicationRoles)
	op(api, http.MethodPut, "set-application-roles", "roles:assign", "/applications/{clientId}/roles", "Set an M2M Application's Roles on its API", s.setApplicationRoles, http.StatusConflict)

	get(api, "list-channels", "config:read", "/channels", "Channel plugins and the enabled Channel of each Identifier kind", s.listChannels)
	op(api, http.MethodPut, "put-channel", "config:write", "/channels/{kind}", "Enable and configure the Channel of an Identifier kind", s.putChannel)
	op(api, http.MethodDelete, "delete-channel", "config:write", "/channels/{kind}", "Turn off codes of an Identifier kind", s.deleteChannel)
	get(api, "list-providers", "config:read", "/providers", "Provider types and the Providers added, with how many Users each signs in", s.listProviders)
	op(api, http.MethodPost, "create-provider", "config:write", "/providers", "Add a Provider", s.createProvider, http.StatusConflict)
	op(api, http.MethodPut, "update-provider", "config:write", "/providers/{id}", "Change a Provider's name and settings; its ID and Immutable fields stay", s.updateProvider)
	op(api, http.MethodPost, "enable-provider", "config:write", "/providers/{id}/enable", "Put a Provider back on the login page", s.enableProvider)
	op(api, http.MethodPost, "disable-provider", "config:write", "/providers/{id}/disable", "Take a Provider off the login page; its Users cannot sign in with it", s.disableProvider)
	op(api, http.MethodDelete, "delete-provider", "config:write", "/providers/{id}", "Delete a Provider no User is bound to", s.deleteProvider, http.StatusConflict)
	get(api, "get-settings", "config:read", "/settings", "The login policy", s.getSettings)
	op(api, http.MethodPut, "put-settings", "config:write", "/settings", "Change the login policy", s.putSettings)
	get(api, "list-signing-keys", "config:read", "/signing-keys", "The token signing keys", s.listKeys)
	op(api, http.MethodPost, "rotate-signing-keys", "keys:rotate", "/signing-keys/rotate", "Make a new signing key current; the oldest is retired", s.rotateKeys)
	op(api, http.MethodPost, "test-channel", "config:write", "/channels/{kind}/test", "Send a test code through the enabled Channel", s.testChannel, http.StatusBadGateway)
}

// get registers a GET operation that needs permission ("" for any admin).
func get[I, O any](api huma.API, id, permission, path, summary string, h func(context.Context, *I) (*O, error)) {
	op(api, http.MethodGet, id, permission, path, summary, h)
}

// op registers an operation that needs permission ("" for any admin).
func op[I, O any](api huma.API, method, id, permission, path, summary string, h func(context.Context, *I) (*O, error), errs ...int) {
	errs = append(errs, http.StatusUnauthorized, http.StatusForbidden)
	if strings.Contains(path, "{") { // names a resource that may not exist
		errs = append(errs, http.StatusNotFound)
	}
	if method != http.MethodGet {
		errs = append(errs, http.StatusUnprocessableEntity)
	}
	huma.Register(api, huma.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Description: describe(permission),
		Errors:      errs,
		Metadata:    map[string]any{"permission": permission},
	}, h)
}

func describe(permission string) string {
	if permission == "" {
		return "Needs any Management API Role."
	}
	return "Needs `" + permission + "`."
}

// authorize checks the bearer token, then the caller's Permissions as they
// stand in PG now: taking a Role away locks the admin out on the next
// request, not when the token expires. The caller is a User, or an M2M
// Application calling as itself (ADR 0015).
func (s *Service) authorize(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		tok, err := s.keys.Verify(ctx.Context(), s.issuer, identity.ManagementAPI, ctx.Header("Authorization"))
		if err != nil {
			ctx.SetHeader("WWW-Authenticate", `Bearer error="invalid_token"`)
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "access token missing or invalid")
			return
		}
		sub := tok.Subject
		c, err := s.q.Caller(ctx.Context(), sqlc.CallerParams{Sub: sub, Api: identity.ManagementAPI})
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "internal error")
			return
		}
		// An M2M Application's token has its client_id as sub, and it holds
		// Roles on the API that the User tables know nothing about.
		call := caller{sub: sub, permissions: c.Permissions, satisfied: c.TwoFactor, totp: c.Totp}
		required, admin := c.TwoFactorRequired, c.Admin
		if !admin {
			a, err := s.q.M2MCaller(ctx.Context(), sqlc.M2MCallerParams{ClientID: sub, Api: identity.ManagementAPI})
			if err != nil {
				_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "internal error")
				return
			}
			// A deleted Application answers false here, so its tokens stop
			// working at once, like a User losing their last Role.
			call.application, call.permissions, admin = a.IsM2mApplication, a.Permissions, a.Admin
		}
		if !admin {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "not an admin")
			return
		}
		// An M2M Application is exempt from 管理员必须启用两步验证或 Passkey:
		// there is no one to turn either on for it. Every other check holds.
		if required && !call.satisfied && !call.application {
			// The console shows a page sending the admin to the account center.
			ctx.SetHeader("Content-Type", "application/problem+json")
			ctx.SetStatus(http.StatusForbidden)
			_ = json.NewEncoder(ctx.BodyWriter()).Encode(struct {
				huma.ErrorModel
				Code string `json:"code"`
			}{huma.ErrorModel{Title: "Forbidden", Status: http.StatusForbidden, Detail: "需要先开启两步验证或添加 Passkey"}, TwoFactorRequired})
			return
		}
		want, _ := ctx.Operation().Metadata["permission"].(string)
		if want != "" && !slices.Contains(call.permissions, want) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "missing permission "+want)
			return
		}
		next(huma.WithValue(ctx, callerKey{}, call))
		s.auditWrite(ctx, sub)
	}
}

type Identifier struct {
	Kind  string `json:"kind" enum:"phone,email,username"`
	Value string `json:"value"`
}

type Role struct {
	API  string `json:"api" doc:"Identifier of the API the Role is on"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type User struct {
	Sub         string       `json:"sub"`
	CreatedAt   time.Time    `json:"createdAt"`
	DisabledAt  *time.Time   `json:"disabledAt,omitempty" doc:"Set while the User is disabled"`
	Pending     bool         `json:"pending" doc:"待激活: an admin created the User and they have not set a password of their own yet; they can sign in but get no token until they do"`
	Identifiers []Identifier `json:"identifiers"`
	Roles       []Role       `json:"roles"`
}

// Invite is what a User's 注册邀请 has come to, as their page shows it.
type Invite struct {
	State     string     `json:"state" enum:"none,sent,accepted" doc:"none: 没发出过 (or it was revoked or has expired); sent: a link is out there and nobody has used it; accepted: the last invite was spent by the User themselves"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" doc:"Set while state is sent: when the link stops working, 7 days after it went out"`
}

type UserDetail struct {
	User
	Nickname           string `json:"nickname,omitempty"`
	Picture            string `json:"picture,omitempty" doc:"The avatar's URL"`
	HasPassword        bool   `json:"hasPassword"`
	TwoFactor          bool   `json:"twoFactor" doc:"两步验证 is on"`
	TwoFactorOrPasskey bool   `json:"twoFactorOrPasskey" doc:"已开启两步验证或仍有至少一把 Passkey"`
	Invite             Invite `json:"invite" doc:"The User's 注册邀请: what the console offers 发出 / 重发 / 撤销 on"`
}

type meOutput struct {
	Body struct {
		Sub         string   `json:"sub"`
		Identifier  string   `json:"identifier" doc:"The caller's primary Identifier: phone, else email, else username; empty for an M2M Application, which has none"`
		Permissions []string `json:"permissions"`
	}
}

func (s *Service) me(ctx context.Context, _ *struct{}) (*meOutput, error) {
	c := ctx.Value(callerKey{}).(caller)
	out := &meOutput{}
	out.Body.Sub, out.Body.Permissions = c.sub, c.permissions
	if c.application {
		return out, nil
	}
	r, err := s.q.GetUser(ctx, c.sub)
	if err != nil {
		return nil, err
	}
	u, err := user(r.ID, r.CreatedAt.Time, r.DisabledAt, r.Pending, r.Identifiers, r.Roles)
	if err != nil {
		return nil, err
	}
	for _, kind := range []string{"phone", "email", "username"} {
		if i := slices.IndexFunc(u.Identifiers, func(i Identifier) bool { return i.Kind == kind }); i >= 0 {
			out.Body.Identifier = u.Identifiers[i].Value
			break
		}
	}
	return out, nil
}

type listUsersInput struct {
	Q      string `query:"q" doc:"Part of a sub, phone number, email or username"`
	Role   string `query:"role" doc:"Only Users holding this Role"`
	API    string `query:"api" doc:"API of the Role filter; defaults to the Management API"`
	Status string `query:"status" default:"any" enum:"any,active,pending" doc:"pending: 待激活 and not disabled; active: everything else, a disabled User included"`
	Limit  int32  `query:"limit" default:"50" minimum:"1" maximum:"200"`
	Offset int32  `query:"offset" minimum:"0"`
}

type listUsersOutput struct {
	Body struct {
		Users   []User `json:"users" nullable:"false"`
		HasMore bool   `json:"hasMore"`
	}
}

func (s *Service) listUsers(ctx context.Context, in *listUsersInput) (*listUsersOutput, error) {
	api := in.API
	if api == "" {
		api = identity.ManagementAPI
	}
	rows, err := s.q.ListUsers(ctx, sqlc.ListUsersParams{
		Search: strings.TrimSpace(in.Q), Role: in.Role, Api: api, Status: in.Status, Lim: in.Limit + 1, Off: in.Offset,
	})
	if err != nil {
		return nil, err
	}
	out := &listUsersOutput{}
	out.Body.Users = []User{}
	for i, r := range rows {
		if i == int(in.Limit) {
			out.Body.HasMore = true
			break
		}
		u, err := user(r.ID, r.CreatedAt.Time, r.DisabledAt, r.Pending, r.Identifiers, r.Roles)
		if err != nil {
			return nil, err
		}
		out.Body.Users = append(out.Body.Users, u)
	}
	return out, nil
}

type getUserOutput struct{ Body UserDetail }

func (s *Service) getUser(ctx context.Context, in *struct {
	Sub string `path:"sub"`
}) (*getUserOutput, error) {
	r, err := s.q.GetUser(ctx, in.Sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error404NotFound("no such User")
	} else if err != nil {
		return nil, err
	}
	u, err := userDetail(r)
	if err != nil {
		return nil, err
	}
	u.Picture = s.profiles.Picture(r.Avatar)
	return &getUserOutput{Body: u}, nil
}

// userDetail is a User's page: the User themselves plus what only their own
// page shows.
func userDetail(r sqlc.GetUserRow) (UserDetail, error) {
	u, err := user(r.ID, r.CreatedAt.Time, r.DisabledAt, r.Pending, r.Identifiers, r.Roles)
	if err != nil {
		return UserDetail{}, err
	}
	return UserDetail{
		User:               u,
		Nickname:           r.Nickname,
		HasPassword:        r.HasPassword,
		TwoFactor:          r.TwoFactor,
		TwoFactorOrPasskey: r.TwoFactorOrPasskey,
		Invite:             invite(r),
	}, nil
}

func user(sub string, created time.Time, disabled pgtype.Timestamptz, pending bool, identifiers, roles []byte) (User, error) {
	u := User{Sub: sub, CreatedAt: created, Pending: pending}
	if disabled.Valid {
		u.DisabledAt = &disabled.Time
	}
	if err := json.Unmarshal(identifiers, &u.Identifiers); err != nil {
		return u, err
	}
	return u, json.Unmarshal(roles, &u.Roles)
}

type RoleInfo struct {
	Role
	APIName string `json:"apiName"`
	Builtin bool   `json:"builtin" doc:"Built-in Roles cannot be changed or deleted"`
}

type listRolesOutput struct {
	Body struct {
		Roles []RoleInfo `json:"roles" nullable:"false"`
	}
}

func (s *Service) listRoles(ctx context.Context, _ *struct{}) (*listRolesOutput, error) {
	rows, err := s.q.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	out := &listRolesOutput{}
	out.Body.Roles = []RoleInfo{}
	for _, r := range rows {
		out.Body.Roles = append(out.Body.Roles, RoleInfo{Role: Role{API: r.Api, Key: r.Key, Name: r.Name}, APIName: r.ApiName, Builtin: r.Builtin})
	}
	return out, nil
}
