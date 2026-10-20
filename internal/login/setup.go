package login

import (
	"errors"
	"net/http"

	"github.com/zibyn/polaris/internal/identity"
)

type setupForm struct {
	Token, Username, Error string
}

// setupPage asks for the first owner's username and password; the link
// printed in the log carries the token.
func (s *Service) setupPage(w http.ResponseWriter, r *http.Request) {
	if open, err := s.ids.SetupToken(r.Context()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else if open == "" {
		page(w, http.StatusNotFound, "message", identity.ErrSetupClosed.Error())
		return
	}
	page(w, http.StatusOK, "setup", setupForm{Token: r.URL.Query().Get("token")})
}

func (s *Service) setup(w http.ResponseWriter, r *http.Request) {
	form := setupForm{Token: r.PostFormValue("token"), Username: r.PostFormValue("username")}
	if err := s.origin.Check(r); err != nil {
		form.Error = "请从引导页提交"
		page(w, http.StatusForbidden, "setup", form)
		return
	}
	_, err := s.ids.Bootstrap(r.Context(), form.Token, form.Username, r.PostFormValue("password"))
	var invalid identity.Invalid
	switch {
	case errors.Is(err, identity.ErrSetupClosed):
		page(w, http.StatusNotFound, "message", err.Error())
	case errors.As(err, &invalid):
		form.Error = invalid.Error()
		page(w, http.StatusOK, "setup", form)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		page(w, http.StatusOK, "message", "所有者已创建。用这个用户名和密码登录管理端。")
	}
}
