// Package server wires the HTTP surface of Polaris.
package server

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"path"
	"strings"
)

// New returns the root handler. Each of routes adds its own; web serves the
// SPA for every path no route claims.
func New(ping func(context.Context) error, web http.Handler, trusted []netip.Prefix, routes ...func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	for _, add := range routes {
		add(mux)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	})
	// An auth service has no home page; users land in the account center.
	mux.Handle("GET /{$}", http.RedirectHandler("/account", http.StatusFound))
	mux.Handle("/", web)
	return trustProxies(trusted, mux)
}

// SPA serves static files from fsys. Any other extension-less path (client
// routes, directories) gets index.html so routes survive a reload and no
// directory is ever listed.
func SPA(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if fi, err := fs.Stat(fsys, p); (err != nil || fi.IsDir()) && path.Ext(p) == "" {
			http.ServeFileFS(w, r, fsys, "index.html")
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
