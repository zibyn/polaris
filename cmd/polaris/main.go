// Command polaris runs the Polaris identity service.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/account"
	// Channel plugins and Provider types register themselves (ADR 0004).
	_ "github.com/zibyn/polaris/internal/channel/aliyun"
	_ "github.com/zibyn/polaris/internal/channel/smtp"
	_ "github.com/zibyn/polaris/internal/channel/webhook"
	"github.com/zibyn/polaris/internal/config"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/login"
	"github.com/zibyn/polaris/internal/management"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/otp"
	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/pow"
	_ "github.com/zibyn/polaris/internal/provider/apple"
	_ "github.com/zibyn/polaris/internal/provider/github"
	_ "github.com/zibyn/polaris/internal/provider/google"
	_ "github.com/zibyn/polaris/internal/provider/microsoft"
	_ "github.com/zibyn/polaris/internal/provider/oauth2"
	_ "github.com/zibyn/polaris/internal/provider/oidc"
	"github.com/zibyn/polaris/internal/server"
	"github.com/zibyn/polaris/internal/webhook"
	"github.com/zibyn/polaris/web"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		err = healthcheck()
	} else {
		err = serve()
	}
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Version 1 until rotate-master-key (phase 2); features that store
	// secrets take the keyring from here.
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: cfg.MasterKey})
	if err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := oidcstore.NewKeys(pool, keyring).Ensure(ctx); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if token, err := identity.New(pool, keyring).SetupToken(ctx); err != nil {
		return fmt.Errorf("setup token: %w", err)
	} else if token != "" {
		slog.Warn("no admin yet: open the setup page to create the owner", "url", cfg.Issuer+"/setup?token="+token)
	}
	auth, err := login.New(ctx, pool, keyring, cfg.Issuer)
	if err != nil {
		return err
	}

	spa, err := webHandler(cfg.DevWebURL)
	if err != nil {
		return err
	}
	accountSvc, err := account.New(pool, keyring, cfg.Issuer)
	if err != nil {
		return err
	}
	managementSvc, err := management.New(pool, keyring, cfg.Issuer)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: server.New(pool.Ping, spa, cfg.TrustedProxies, auth.Register,
			managementSvc.Register, accountSvc.Register),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go runCleanup(ctx, pool)
	go webhook.New(pool, keyring).Run(ctx)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			slog.Error("shutdown", "err", err)
		}
	}()
	slog.Info("listening", "addr", cfg.Listen, "issuer", cfg.Issuer)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained // in-flight requests finish before the pool closes
	return nil
}

// webHandler serves the embedded SPA, or in development proxies to a Vite
// dev server so the browser still talks to a single origin (HMR included).
func webHandler(devURL string) (http.Handler, error) {
	if devURL != "" {
		u, err := url.Parse(devURL)
		if err != nil {
			return nil, err
		}
		slog.Warn("proxying web UI to dev server", "url", devURL)
		return httputil.NewSingleHostReverseProxy(u), nil
	}
	dist, err := fs.Sub(web.Dist, "dist/client")
	if err != nil {
		return nil, err
	}
	return server.SPA(dist), nil
}

// cleanupTasks delete expired short-lived rows (codes, PoW, rate limits,
// grants). Each feature adds its own as its table lands.
var cleanupTasks = []func(context.Context, *pgxpool.Pool) error{
	oidcstore.DeleteExpired,
	login.DeleteOldSessions,
	otp.DeleteExpired,
	pow.DeleteExpired,
	passkey.DeleteExpired,
	management.DeleteOldAudit,
	identity.DeleteOldLoginFailures,
	identity.DeleteExpiredInvites,
}

// runCleanup runs cleanupTasks once an hour.
func runCleanup(ctx context.Context, pool *pgxpool.Pool) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, task := range cleanupTasks {
				if err := task(ctx, pool); err != nil {
					slog.Error("cleanup", "err", err)
				}
			}
		}
	}
}

// healthcheck probes /healthz on the local listener; used by the container
// HEALTHCHECK since the distroless image has no curl.
func healthcheck() error {
	listen := os.Getenv("POLARIS_LISTEN")
	if listen == "" {
		listen = config.DefaultListen
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
