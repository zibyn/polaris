package login

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// corsMethods are the OIDC endpoints a cross-origin SPA (public + PKCE)
// calls, with the methods it may use; the provider's default paths (#140).
var corsMethods = map[string]string{
	"/token":    "POST",
	"/revoke":   "POST",
	"/userinfo": "GET, POST",
	// Public metadata: any origin.
	"/.well-known/openid-configuration": "GET",
	"/jwks":                             "GET",
}

func isPublic(path string) bool { return corsMethods[path] == "GET" }

// cors adds CORS headers on the endpoints in corsMethods. token, revoke and
// userinfo allow the origin of any Application's redirect URI, whatever the
// client: a preflight names none, and PKCE and the bearer token are what
// protect them. Others pass through untouched.
func (s *Service) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := corsMethods[r.URL.Path]; ok {
			if isPublic(r.URL.Path) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Add("Vary", "Origin")
				if origin := r.Header.Get("Origin"); origin != "" && s.redirectOrigin(r, origin) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// preflight answers OPTIONS on the endpoints in corsMethods, after cors.
func preflight(w http.ResponseWriter, r *http.Request) {
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", corsMethods[r.URL.Path])
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

// redirectOrigin reports whether origin is the Web origin of some
// Application's redirect URI, read now so a change applies at once.
// shortcut: reads every Application per request; cache it if it shows up.
func (s *Service) redirectOrigin(r *http.Request, origin string) bool {
	apps, err := s.q.ListApplications(r.Context(), "")
	if err != nil {
		slog.Error("cors origins", "err", err)
		return false
	}
	for _, app := range apps {
		for _, uri := range app.RedirectUris {
			if webOrigin(uri) == origin {
				return true
			}
		}
	}
	return false
}

// webOrigin is uri's origin as a browser serializes it, or "" for a URI
// with none (an App's custom scheme).
func webOrigin(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}
