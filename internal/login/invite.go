package login

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zibyn/stars-auth/internal/identity"
)

type inviteForm struct {
	Token, Error string
}

// invitePage is where a 注册邀请 link lands. A link that was used, revoked or
// has expired says so in the words of ErrInviteSpent and points at the admin;
// it is not the 验证码 failure wording, because no code is involved.
func (s *Service) invitePage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	live, err := s.ids.InviteLive(r.Context(), token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !live {
		page(w, http.StatusNotFound, "message", identity.ErrInviteSpent.Error())
		return
	}
	page(w, http.StatusOK, "invite", inviteForm{Token: token})
}

// acceptInvite is 接受: the password the User sets is their own — the admin
// never saw it — and the browser is signed in on the spot, so the Application
// they came from goes on without a second login. The mailbox is what the link
// proved, so amr is the same otp a code to an email gives (RFC 8176).
func (s *Service) acceptInvite(w http.ResponseWriter, r *http.Request) {
	form := inviteForm{Token: r.PostFormValue("token")}
	if err := s.origin.Check(r); err != nil {
		form.Error = "请从邀请链接打开本页"
		page(w, http.StatusForbidden, "invite", form)
		return
	}
	sub, err := s.ids.AcceptInvite(r.Context(), form.Token, r.PostFormValue("password"))
	var invalid identity.Invalid
	switch {
	case errors.Is(err, identity.ErrInviteSpent):
		// Spent, revoked, expired or disabled: all of them are "this link is
		// no good, ask your admin", and telling them apart helps nobody.
		page(w, http.StatusNotFound, "message", err.Error())
		return
	case errors.As(err, &invalid):
		form.Error = invalid.Error()
		page(w, http.StatusOK, "invite", form)
		return
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A Session starts here only when nothing else stands between the User and
	// one. An invite link proves the same thing an emailed code does, so it
	// earns the same session a code login does and no more: 两步验证, 绑手机号
	// and 同意协议 come first, as they do for every other first factor. With
	// anything left, the account center's own sign-in runs it — the password
	// they just set is what they use.
	amr := []string{string(codeAMR("email"))}
	more, err := s.moreBeforeSession(r.Context(), sub, amr)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !more {
		if _, err := s.newSession(w, r, AccountClientID, sub, time.Now(), amr); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// moreBeforeSession reports whether 两步验证, 绑手机号 or 同意协议 still stand
// between sub and a browser Session — the three complete() runs after a first
// factor. A caller that has just proved one factor asks this before starting a
// Session of its own. 待激活 is not one of them: whoever asks has cleared it.
func (s *Service) moreBeforeSession(ctx context.Context, sub string, amr []string) (bool, error) {
	if totp, err := s.needsTOTP(ctx, sub, amr); err != nil || totp {
		return totp, err
	}
	if phone, err := s.q.NeedsPhone(ctx, sub); err != nil || phone {
		return phone, err
	}
	return s.q.NeedsConsent(ctx, sub)
}
