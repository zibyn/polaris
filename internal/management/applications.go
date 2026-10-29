package management

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidcstore"
)

// ApplicationSettings are what an admin edits on an Application.
type ApplicationSettings struct {
	Name                   string       `json:"name" minLength:"1" maxLength:"64"`
	RedirectURIs           []string     `json:"redirectUris" nullable:"false"`
	PostLogoutRedirectURIs []string     `json:"postLogoutRedirectUris" nullable:"false"`
	DefaultAPI             string       `json:"defaultApi,omitempty" doc:"Identifier of the API its access tokens are for; empty for none"`
	SessionIdleTimeout     int32        `json:"sessionIdleTimeout,omitempty" minimum:"0" maximum:"31536000" doc:"Seconds a Session may sit idle; 0 for the default (30 days browser, 90 days App)"`
	RefreshTokens          bool         `json:"refreshTokens"`
	RequireRole            bool         `json:"requireRole,omitempty" doc:"Turn away a User without a Role on the default API: no authorization code, no refresh. Needs a default API; not for M2M Applications"`
	WebhookURL             string       `json:"webhookUrl,omitempty" doc:"Where User events (user.deleted, user.disabled, user.enabled, user.updated) are sent; empty for none"`
	WebhookSecret          string       `json:"webhookSecret,omitempty" writeOnly:"true" doc:"Key the webhook is signed with; empty keeps the stored one. Never read back."`
	BackchannelLogoutURI   string       `json:"backchannelLogoutUri,omitempty" doc:"Where OIDC Back-Channel Logout tokens are sent when a Session ends; Web (confidential) Applications only, empty for none"`
	AppleAppIDs            []string     `json:"appleAppIds" nullable:"false" doc:"Team ID + Bundle ID, as ABCDE12345.com.example.app"`
	AndroidApps            []AndroidApp `json:"androidApps" nullable:"false"`
}

type AndroidApp struct {
	PackageName            string   `json:"packageName"`
	SHA256CertFingerprints []string `json:"sha256CertFingerprints" nullable:"false" doc:"As AB:CD:…, 32 bytes"`
}

type Application struct {
	ClientID  string    `json:"clientId"`
	Type      string    `json:"type" enum:"public,confidential,m2m" doc:"Confidential Applications authenticate with a client secret; public ones (Apps, SPAs) with PKCE only; an m2m one is a backend service calling an API as itself"`
	Builtin   bool      `json:"builtin" doc:"The console: read-only"`
	CreatedAt time.Time `json:"createdAt"`
	ApplicationSettings
	WebhookSecretUpdatedAt *time.Time `json:"webhookSecretUpdatedAt,omitempty" doc:"When the webhook signing key was last set"`
}

type clientIDPath struct {
	ClientID string `path:"clientId"`
}

type listApplicationsOutput struct {
	Body struct {
		Applications []Application `json:"applications" nullable:"false"`
	}
}

func (s *Service) listApplications(ctx context.Context, _ *struct{}) (*listApplicationsOutput, error) {
	apps, err := s.applications(ctx, "")
	out := &listApplicationsOutput{}
	out.Body.Applications = apps
	return out, err
}

type applicationOutput struct{ Body Application }

func (s *Service) getApplication(ctx context.Context, in *clientIDPath) (*applicationOutput, error) {
	app, err := s.application(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	return &applicationOutput{Body: app}, nil
}

// application is one Application, or a 404.
func (s *Service) application(ctx context.Context, clientID string) (Application, error) {
	apps, err := s.applications(ctx, clientID)
	if err == nil && len(apps) == 0 {
		err = huma.Error404NotFound("no such Application")
	}
	if err != nil {
		return Application{}, err
	}
	return apps[0], nil
}

func (s *Service) applications(ctx context.Context, clientID string) ([]Application, error) {
	rows, err := s.q.ListApplications(ctx, clientID)
	if err != nil {
		return nil, err
	}
	apps := []Application{}
	for _, r := range rows {
		a := Application{
			ClientID: r.ClientID, Type: r.Type, Builtin: r.Builtin, CreatedAt: r.CreatedAt.Time,
			ApplicationSettings: ApplicationSettings{
				Name: r.Name, RedirectURIs: r.RedirectUris, PostLogoutRedirectURIs: r.PostLogoutRedirectUris,
				DefaultAPI: r.DefaultApi, SessionIdleTimeout: r.SessionIdleTimeout, RefreshTokens: r.RefreshTokens,
				RequireRole: r.RequireRole, WebhookURL: r.WebhookUrl, BackchannelLogoutURI: r.BackchannelLogoutUri, AppleAppIDs: r.AppleAppIds,
			},
		}
		if r.WebhookSecretUpdatedAt.Valid {
			a.WebhookSecretUpdatedAt = &r.WebhookSecretUpdatedAt.Time
		}
		if err := json.Unmarshal(r.AndroidApps, &a.AndroidApps); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, nil
}

type createApplicationInput struct {
	Body struct {
		Type     string              `json:"type" enum:"public,confidential,m2m"`
		Settings ApplicationSettings `json:"settings"`
	}
}

type createApplicationOutput struct {
	Body struct {
		Application Application `json:"application"`
		Secret      string      `json:"secret,omitempty" doc:"The client secret of a confidential Application; shown this once"`
	}
}

func (s *Service) createApplication(ctx context.Context, in *createApplicationInput) (*createApplicationOutput, error) {
	out := &createApplicationOutput{}
	clientID := rand.Text()
	var secretHash []byte
	if in.Body.Type != "public" {
		out.Body.Secret = rand.Text()
		secretHash = oidcstore.SecretHash(out.Body.Secret)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.InsertApplication(ctx, sqlc.InsertApplicationParams{ClientID: clientID, Type: in.Body.Type, SecretHash: secretHash}); err != nil {
			return err
		}
		_, err := s.saveSettings(ctx, q, clientID, in.Body.Type, &in.Body.Settings)
		return err
	})
	if err != nil {
		return nil, err
	}
	out.Body.Application, err = s.application(ctx, clientID)
	return out, err
}

func (s *Service) updateApplication(ctx context.Context, in *struct {
	ClientID string `path:"clientId"`
	Body     ApplicationSettings
}) (*struct{}, error) {
	app, err := s.application(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	if app.Builtin {
		return nil, errBuiltinApplication
	}
	// Its default API is the one API it may call, and Roles hang off it
	// (ADR 0015).
	if app.Type == "m2m" && in.Body.DefaultAPI != app.DefaultAPI {
		return nil, huma.Error422UnprocessableEntity("M2M Application 的默认 API 创建后不可改")
	}
	_, err = s.saveSettings(ctx, s.q, in.ClientID, app.Type, &in.Body)
	return nil, err
}

// errBuiltinApplication refuses to touch an Application the authentication
// service owns.
var errBuiltinApplication = huma.Error409Conflict("内置 Application 不能修改或删除")

// notBuiltin explains why an Application was left alone: 404 or 409.
func (s *Service) notBuiltin(ctx context.Context, clientID string) error {
	app, err := s.application(ctx, clientID)
	if err == nil && app.Builtin {
		err = errBuiltinApplication
	}
	return err
}

var (
	appleAppID  = regexp.MustCompile(`^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$`)
	packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
	certSHA256  = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)
)

func (st *ApplicationSettings) validate(typ string) error {
	// An M2M Application only ever calls its one API as itself: no login, so
	// nothing to redirect to and no native App to associate. Its default API
	// picks which API that is, and may be the Management API (ADR 0015).
	if typ == "m2m" {
		if st.DefaultAPI == "" {
			return identity.Invalid("M2M Application 必须有默认 API")
		}
		if len(st.RedirectURIs) > 0 || len(st.PostLogoutRedirectURIs) > 0 {
			return identity.Invalid("M2M Application 不登录,没有回调地址")
		}
		if len(st.AppleAppIDs) > 0 || len(st.AndroidApps) > 0 {
			return identity.Invalid("M2M Application 不关联原生 App")
		}
		if st.RequireRole {
			return identity.Invalid("M2M Application 没有 User 登录,不能要求 Role")
		}
	}
	// The Roles checked are the ones on the default API.
	if st.RequireRole && st.DefaultAPI == "" {
		return identity.Invalid("要求 Role 需要先设置默认 API")
	}
	// Its tokens would let the Application act as any admin who signs in to
	// it, or as any User on their own account.
	if typ != "m2m" && st.DefaultAPI == identity.ManagementAPI {
		return identity.Invalid("Management API 只供管理端使用")
	}
	if st.DefaultAPI == identity.AccountAPI {
		return identity.Invalid("Account API 只供账号中心使用")
	}
	for _, u := range append(append([]string{}, st.RedirectURIs...), st.PostLogoutRedirectURIs...) {
		if p, err := url.Parse(u); err != nil || !p.IsAbs() || p.Fragment != "" || len(u) > 2048 {
			return identity.Invalid("回调地址须为完整 URI,不带 #:" + u)
		}
	}
	if st.WebhookURL != "" {
		if p, err := url.Parse(st.WebhookURL); err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return identity.Invalid("webhook URL 须为 http(s) 地址")
		}
	}
	// Only a Web Application has a back end to tell (ADR 0022).
	if st.BackchannelLogoutURI != "" {
		if typ != "confidential" {
			return identity.Invalid("只有 Web Application 能配置 Back-Channel Logout")
		}
		if p, err := url.Parse(st.BackchannelLogoutURI); err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || p.Fragment != "" {
			return identity.Invalid("Back-Channel Logout URI 须为 http(s) 地址,不带 #")
		}
	}
	for _, id := range st.AppleAppIDs {
		if !appleAppID.MatchString(id) {
			return identity.Invalid("Apple App ID 须为 Team ID.Bundle ID:" + id)
		}
	}
	for _, a := range st.AndroidApps {
		if !packageName.MatchString(a.PackageName) {
			return identity.Invalid("Android 包名不对:" + a.PackageName)
		}
		for _, f := range a.SHA256CertFingerprints {
			if !certSHA256.MatchString(f) {
				return identity.Invalid("签名指纹须为 SHA-256,如 AB:CD:…:" + f)
			}
		}
	}
	return nil
}

// saveSettings writes an Application's settings; 0 rows for a built-in or
// missing one.
func (s *Service) saveSettings(ctx context.Context, q *sqlc.Queries, clientID, typ string, st *ApplicationSettings) (int64, error) {
	if err := invalid(st.validate(typ)); err != nil {
		return 0, err
	}
	var secret []byte
	if st.WebhookSecret != "" {
		var err error
		if secret, err = s.keyring.Seal([]byte(st.WebhookSecret), []byte("application:"+clientID+":webhook")); err != nil {
			return 0, err
		}
	}
	android, err := json.Marshal(append([]AndroidApp{}, st.AndroidApps...))
	if err != nil {
		return 0, err
	}
	n, err := q.UpdateApplication(ctx, sqlc.UpdateApplicationParams{
		ClientID: clientID, Name: st.Name,
		RedirectUris:           append([]string{}, st.RedirectURIs...),
		PostLogoutRedirectUris: append([]string{}, st.PostLogoutRedirectURIs...),
		DefaultApi:             st.DefaultAPI, IdleSecs: st.SessionIdleTimeout, RefreshTokens: st.RefreshTokens,
		RequireRole: st.RequireRole, WebhookUrl: st.WebhookURL, WebhookSecret: secret, BackchannelLogoutUri: st.BackchannelLogoutURI,
		AppleAppIds: append([]string{}, st.AppleAppIDs...), AndroidApps: android,
	})
	var pg *pgconn.PgError
	switch {
	case isFKViolation(err):
		return 0, huma.Error422UnprocessableEntity("没有这个 API")
	case errors.As(err, &pg) && pg.ConstraintName == "applications_webhook_check":
		return 0, huma.Error422UnprocessableEntity("webhook 需要签名密钥")
	}
	return n, err
}

func (s *Service) deleteApplication(ctx context.Context, in *clientIDPath) (*struct{}, error) {
	if err := s.notBuiltin(ctx, in.ClientID); err != nil {
		return nil, err
	}
	return nil, s.q.DeleteApplication(ctx, in.ClientID)
}

// ApplicationRoles are the Roles an M2M Application holds on its default API;
// its client_credentials token carries them (ADR 0015).
type ApplicationRoles struct {
	API   string   `json:"api" doc:"Identifier of the API the Roles are on; the Application's default API"`
	Roles []string `json:"roles" nullable:"false" doc:"Keys of every Role it holds"`
}

type applicationRolesOutput struct{ Body ApplicationRoles }

func (s *Service) listApplicationRoles(ctx context.Context, in *clientIDPath) (*applicationRolesOutput, error) {
	app, err := s.application(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	out := &applicationRolesOutput{}
	out.Body.API = app.DefaultAPI
	out.Body.Roles, err = s.q.ApplicationRoles(ctx, sqlc.ApplicationRolesParams{ClientID: in.ClientID, Api: app.DefaultAPI})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type setApplicationRolesInput struct {
	ClientID string `path:"clientId"`
	Body     struct {
		Roles []string `json:"roles" nullable:"false" doc:"Keys of every Role it should hold on its default API; Roles left out are taken away"`
	}
}

func (s *Service) setApplicationRoles(ctx context.Context, in *setApplicationRolesInput) (*struct{}, error) {
	app, err := s.application(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	// Only an M2M Application calls an API as itself, and only on its one
	// default API; the Role has to live there (ADR 0015).
	if app.Type != "m2m" {
		return nil, huma.Error422UnprocessableEntity("只有 M2M Application 能持有 Role")
	}
	if app.DefaultAPI == identity.ManagementAPI {
		if err := mayMakeAdmins(ctx); err != nil {
			return nil, err
		}
		// 「所有者」is a person; an Application never is one.
		if slices.Contains(in.Body.Roles, "owner") {
			return nil, huma.Error422UnprocessableEntity("「所有者」不能分配给 Application")
		}
	}
	err = s.q.SetApplicationRoles(ctx, sqlc.SetApplicationRolesParams{ClientID: in.ClientID, Api: app.DefaultAPI, Roles: in.Body.Roles, By: callerSub(ctx)})
	if isFKViolation(err) {
		return nil, huma.Error422UnprocessableEntity("没有这个 Role")
	}
	return nil, err
}

// registerAssociation serves the /.well-known/ association files iOS and
// Android read to let the registered native Apps use this domain's
// Passkeys and password autofill. Not behind the Passkey switch: password
// autofill needs them too (docs/spec/authentication.md「密码管理器适配」).
func (s *Service) registerAssociation(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/apple-app-site-association", func(w http.ResponseWriter, r *http.Request) {
		apps, err := s.applications(r.Context(), "")
		if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		ids := []string{}
		for _, a := range apps {
			ids = append(ids, a.AppleAppIDs...)
		}
		writeJSON(w, map[string]map[string][]string{"webcredentials": {"apps": ids}})
	})
	mux.HandleFunc("GET /.well-known/assetlinks.json", func(w http.ResponseWriter, r *http.Request) {
		apps, err := s.applications(r.Context(), "")
		if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		statements := []map[string]any{}
		for _, a := range apps {
			for _, android := range a.AndroidApps {
				statements = append(statements, map[string]any{
					"relation": []string{
						"delegate_permission/common.get_login_creds",
						"delegate_permission/common.handle_all_urls",
					},
					"target": map[string]any{
						"namespace":                "android_app",
						"package_name":             android.PackageName,
						"sha256_cert_fingerprints": android.SHA256CertFingerprints,
					},
				})
			}
		}
		writeJSON(w, statements)
	})
}

// writeJSON answers with a JSON body, no redirect.
func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

type newSecretOutput struct {
	Body struct {
		Secret string `json:"secret" doc:"The new client secret; shown this once. The old one stops working."`
	}
}

func (s *Service) newSecret(ctx context.Context, in *clientIDPath) (*newSecretOutput, error) {
	out := &newSecretOutput{}
	out.Body.Secret = rand.Text()
	n, err := s.q.SetApplicationSecret(ctx, sqlc.SetApplicationSecretParams{ClientID: in.ClientID, SecretHash: oidcstore.SecretHash(out.Body.Secret)})
	if err != nil || n > 0 {
		return out, err
	}
	if err := s.notBuiltin(ctx, in.ClientID); err != nil {
		return nil, err
	}
	return nil, huma.Error409Conflict("public Application 没有 client secret")
}
