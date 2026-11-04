package login

import (
	"errors"
	"net/http"
	"time"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/oidc/goidc"
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
		s.page(w, r, "", "", http.StatusNotFound, "message", identity.ErrSetupClosed.Error())
		return
	}
	s.page(w, r, "", "", http.StatusOK, "setup", setupForm{Token: r.URL.Query().Get("token")})
}

func (s *Service) setup(w http.ResponseWriter, r *http.Request) {
	form := setupForm{Token: r.PostFormValue("token"), Username: r.PostFormValue("username")}
	if err := s.origin.Check(r); err != nil {
		form.Error = "请从引导页提交"
		s.page(w, r, "", "", http.StatusForbidden, "setup", form)
		return
	}
	sub, err := s.ids.Bootstrap(r.Context(), form.Token, form.Username, r.PostFormValue("password"))
	var invalid identity.Invalid
	switch {
	case errors.Is(err, identity.ErrSetupClosed):
		s.page(w, r, "", "", http.StatusNotFound, "message", err.Error())
	case errors.As(err, &invalid):
		form.Error = invalid.Error()
		s.page(w, r, "", "", http.StatusOK, "setup", form)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		// The owner is made and the setup page is closed. They just proved
		// the password by choosing it, so they are signed in with it rather
		// than asked to type it again, as an accepted invite is; whatever
		// else a login needs first (nextStep) leaves it to the login page.
		amr := []string{string(goidc.AMRPassword)}
		what, err := s.nextStep(r.Context(), sub, amr, false)
		if err == nil && what == stepDone {
			_, err = s.newSession(w, r, identity.ConsoleClientID, sub, time.Now(), amr, identity.MethodPassword)
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/console", http.StatusSeeOther)
	}
}
