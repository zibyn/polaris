// Package authutil contains utilities to set up example authorization server
// using goidc.
package authutil

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/zibyn/polaris/internal/oidc/conformance/keys"
	"github.com/zibyn/polaris/internal/oidc/conformance/ui"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// Issuer is overridable so the harness can run where port 443 is not bindable.
var Issuer = cmp.Or(os.Getenv("ISSUER"), "https://auth.localhost")

var (
	Scopes = []goidc.Scope{
		goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeProfile,
		goidc.ScopeEmail, goidc.ScopeAddress, goidc.ScopePhone,
	}
	Claims = []string{
		goidc.ClaimEmail, goidc.ClaimEmailVerified, goidc.ClaimPhoneNumber,
		goidc.ClaimPhoneNumberVerified, goidc.ClaimAddress,
	}
	ACRs          = []goidc.ACR{goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver}
	DisplayValues = []goidc.DisplayValue{goidc.DisplayValuePage, goidc.DisplayValuePopup}
)

var (
	errLogoutCancelled error = errors.New("logout cancelled by the user")
)

func ServerCert() tls.Certificate {
	certBytes, err := keys.FS.ReadFile("server.crt")
	if err != nil {
		log.Fatal(err)
	}

	keyBytes, err := keys.FS.ReadFile("server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		log.Fatal(err)
	}

	return tlsCert
}

func TokenOptionsFunc(alg goidc.SignatureAlgorithm) goidc.TokenOptionsFunc {
	return func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(alg, 600)
		return opts
	}
}

func IDTokenClaimsFunc() goidc.IDTokenClaimsFunc {
	return func(_ context.Context, grant *goidc.Grant) map[string]any {
		claims, _ := grant.Store[paramIDTokenClaims].(map[string]any)
		return claims
	}
}

func UserInfoClaimsFunc() goidc.UserInfoClaimsFunc {
	return func(_ context.Context, grant *goidc.Grant) map[string]any {
		claims, _ := grant.Store[paramUserInfoClaims].(map[string]any)
		return claims
	}
}

func HTTPClient(_ context.Context) *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func HandleError(ctx context.Context, err error) {
	log.Printf("error: %s\n", err.Error())
}

func RenderError() goidc.RenderErrorFunc {
	tmpl := template.Must(template.ParseFS(ui.FS, "template.html"))
	return func(w http.ResponseWriter, r *http.Request, err error) error {
		w.WriteHeader(http.StatusOK)
		_ = tmpl.ExecuteTemplate(w, "error", authnPage{
			Error: err.Error(),
		})
		return nil
	}

}

func PairwiseSubjectFunc() goidc.PairwiseSubjectFunc {
	return func(_ context.Context, sub string, _ *goidc.Client) string {
		return sub
	}
}

func ConsumeJTIFunc() goidc.ConsumeJTIFunc {
	jtiStore := make(map[string]struct{})
	return func(ctx context.Context, jti string) error {
		if _, ok := jtiStore[jti]; ok {
			return errors.New("jti already used")
		}

		jtiStore[jti] = struct{}{}
		return nil
	}
}

type LogoutPage struct {
	BaseURL     string
	CallbackID  string
	IsLoggedOut bool
	Session     map[string]any
}

func LogoutPolicy() goidc.LogoutPolicy {

	tmpl := template.Must(template.ParseFS(ui.FS, "template.html"))
	return goidc.NewLogoutPolicy(
		"main",
		func(r *http.Request, ls *goidc.LogoutSession) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
			logout := r.PostFormValue("logout")
			if logout == "" {
				slog.Debug("rendering logout page")
				if err := tmpl.ExecuteTemplate(w, "logout", LogoutPage{
					BaseURL:    Issuer,
					CallbackID: ls.ID,
					Session:    mapify(ls),
				}); err != nil {
					return goidc.StatusFailure, err
				}
				return goidc.StatusPending, nil
			}

			if logout != "true" {
				slog.Debug("user cancelled logout")
				return goidc.StatusFailure, errLogoutCancelled
			}

			cookie, err := r.Cookie(cookieUserSessionID)
			if err != nil {
				slog.Debug("the session cookie was not found", "error", err)
				return goidc.StatusSuccess, nil
			}

			delete(userSessionStore, cookie.Value)
			return goidc.StatusSuccess, nil
		},
	)
}

func HandleLogout() goidc.HandleDefaultPostLogoutFunc {
	tmpl := template.Must(template.ParseFS(ui.FS, "template.html"))
	return func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) error {
		if err := tmpl.ExecuteTemplate(w, "logout", LogoutPage{IsLoggedOut: true}); err != nil {
			return fmt.Errorf("could not execute logout template: %w", err)
		}
		return nil
	}
}
