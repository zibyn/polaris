package management

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
)

// Policy is the login policy (docs/spec/consoles.md, 安全).
type Policy struct {
	PasswordLogin       string `json:"passwordLogin" enum:"off,on" doc:"Whether Users can sign in with a password"`
	RequirePhone        bool   `json:"requirePhone" doc:"Every User must bind a phone number"`
	DailySendLimit      int32  `json:"dailySendLimit" minimum:"0" doc:"Codes the instance sends a day at most"`
	TermsURL            string `json:"termsUrl" doc:"用户协议; https"`
	PrivacyURL          string `json:"privacyUrl" doc:"隐私政策; https"`
	TermsVersion        string `json:"termsVersion" maxLength:"64" doc:"Users agree to this version on their next login after it changes; empty for no terms"`
	AuditRetentionDays  int32  `json:"auditRetentionDays" minimum:"1"`
	AdminsNeedTwoFactor bool   `json:"adminsNeedTwoFactor" doc:"管理员必须启用两步验证或 Passkey: Users holding a Management API Role can't use it without 两步验证 or a Passkey; only an admin who has either turns it on"`
	PasskeyLogin        bool   `json:"passkeyLogin" doc:"The instance offers Passkey login (default true): off hides every Passkey entry, refuses every ceremony, and stops Passkeys from satisfying 管理员必须启用两步验证或 Passkey, while keeping the added ones"`
}

type policyBody struct{ Body Policy }

func (s *Service) getSettings(ctx context.Context, _ *struct{}) (*policyBody, error) {
	r, err := s.q.GetSettings(ctx)
	return &policyBody{Body: Policy{
		PasswordLogin: r.PasswordLogin, RequirePhone: r.RequirePhone, DailySendLimit: r.DailySendLimit,
		TermsURL: r.TermsUrl, PrivacyURL: r.PrivacyUrl, TermsVersion: r.TermsVersion, AuditRetentionDays: r.AuditRetentionDays,
		AdminsNeedTwoFactor: r.AdminsNeedTwoFactor, PasskeyLogin: r.PasskeyLogin,
	}}, err
}

func (s *Service) putSettings(ctx context.Context, in *policyBody) (*struct{}, error) {
	b := in.Body
	if b.TermsVersion != "" && (b.TermsURL == "" || b.PrivacyURL == "") {
		return nil, huma.Error422UnprocessableEntity("填写协议版本时,须同时填写用户协议和隐私政策的 URL")
	}
	for _, u := range []string{b.TermsURL, b.PrivacyURL} {
		if u != "" && !isHTTPS(u) {
			return nil, huma.Error422UnprocessableEntity("协议 URL 须为 https")
		}
	}
	c := ctx.Value(callerKey{}).(caller)
	// With password login off, an admin who has nothing else to sign in with
	// is out of the console for good; refuse rather than let them do it. An
	// M2M Application holds no Identifiers, so it has nothing to lose.
	if b.PasswordLogin == "off" && !c.application {
		otherPath, err := s.ids.OtherLoginPath(ctx, c.sub)
		if err != nil {
			return nil, err
		}
		if !otherPath {
			return nil, huma.Error422UnprocessableEntity("请先为自己绑定邮箱、手机号或外部账号,关闭密码登录后你就进不了管理端了")
		}
	}
	// With the switch on, an admin here satisfies it (两步验证 or a Passkey)
	// already; this stops one turning it on and locking themselves out.
	if b.AdminsNeedTwoFactor && !c.satisfied {
		return nil, huma.Error422UnprocessableEntity("请先为自己开启两步验证")
	}
	// Turning the Passkey switch off takes away the requirement's only
	// satisfaction for an admin whose own is a Passkey: refuse rather than
	// leave them locked out of the Management API on their next request.
	if !b.PasskeyLogin && b.AdminsNeedTwoFactor && c.satisfied && !c.totp {
		return nil, huma.Error422UnprocessableEntity("请先为自己开启两步验证")
	}
	return nil, s.q.UpdateSettings(ctx, sqlc.UpdateSettingsParams{
		By: c.sub, PasswordLogin: b.PasswordLogin, RequirePhone: b.RequirePhone, DailySendLimit: b.DailySendLimit,
		TermsUrl: b.TermsURL, PrivacyUrl: b.PrivacyURL, TermsVersion: b.TermsVersion, AuditRetentionDays: b.AuditRetentionDays,
		AdminsNeedTwoFactor: b.AdminsNeedTwoFactor, PasskeyLogin: b.PasskeyLogin,
	})
}

func isHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

type SigningKey struct {
	Kid       string    `json:"kid"`
	CreatedAt time.Time `json:"createdAt"`
	Current   bool      `json:"current" doc:"Signs new tokens; the other one only verifies tokens it signed"`
}

type listKeysOutput struct {
	Body struct {
		Keys []SigningKey `json:"keys" nullable:"false" doc:"Newest first"`
	}
}

func (s *Service) listKeys(ctx context.Context, _ *struct{}) (*listKeysOutput, error) {
	rows, err := s.q.ListSigningKeys(ctx)
	out := &listKeysOutput{}
	out.Body.Keys = []SigningKey{}
	for i, r := range rows {
		out.Body.Keys = append(out.Body.Keys, SigningKey{Kid: r.Kid, CreatedAt: r.CreatedAt.Time, Current: i == 0})
	}
	return out, err
}

func (s *Service) rotateKeys(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := s.keys.Rotate(ctx); err != nil {
		return nil, err
	}
	c := ctx.Value(callerKey{}).(caller)
	detail, _ := json.Marshal(map[string]string{"by": c.sub})
	return nil, s.q.Audit(ctx, sqlc.AuditParams{Event: "keys.rotated", Detail: detail})
}

// DeleteOldAudit removes audit events past the retention period; run by
// the hourly cleanup.
func DeleteOldAudit(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteOldAudit(ctx)
}
