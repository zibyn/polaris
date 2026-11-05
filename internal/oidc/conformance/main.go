// Command conformance runs the OP that the OpenID conformance suite tests in
// CI (see run.sh), with the production PG storage and signing keys. Login and
// consent pages are test fixtures, not product UI.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/oidc/conformance/authutil"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/provider"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/webhook"
)

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatal(err)
	}
	// A fixed test master key: the conformance database is thrown away.
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		log.Fatal(err)
	}
	keys := oidcstore.NewKeys(pool, keyring)
	if err := keys.Ensure(ctx); err != nil {
		log.Fatal(err)
	}
	store := oidcstore.New(pool, keyring)
	authutil.UseSessions(store, pool)
	scopes := make([]string, len(authutil.Scopes))
	for i, s := range authutil.Scopes {
		scopes[i] = s.ID
	}
	store.Scopes = strings.Join(scopes, " ")
	if err := createClients(ctx, pool, store); err != nil {
		log.Fatal(err)
	}
	// Delivers the logout tokens that ending a Session queues for the Apps
	// with a back-channel URI (ADR 0022). The suite's endpoint is self-signed.
	client := authutil.HTTPClient(ctx)
	client.Timeout = 10 * time.Second
	sender := webhook.New(pool, keyring, authutil.Issuer)
	sender.SetHTTPClient(client)
	go sender.Run(ctx)

	op, err := provider.New(
		provider.Config{
			Issuer:      authutil.Issuer,
			Manager:     store,
			JWKS:        keys.JWKS,
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgNone},
		},
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserInfoSignatureAlgs(goidc.SigAlgRS256, goidc.SigAlgNone),
		provider.WithSecretBasicAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithPrivateKeyJWTAuthn(goidc.SigAlgRS256),
		provider.WithAuthCodeGrant(
			provider.AuthCodeGrantConfig{
				Manager: store,
				ResponseTypes: []goidc.ResponseType{
					goidc.ResponseTypeCode,
					goidc.ResponseTypeIDToken,
					goidc.ResponseTypeToken,
					goidc.ResponseTypeCodeAndIDToken,
					goidc.ResponseTypeCodeAndToken,
					goidc.ResponseTypeIDTokenAndToken,
					goidc.ResponseTypeCodeAndIDTokenAndToken,
				},
			},
			provider.WithIssuerResponseParameter(),
			provider.WithClaimsParameter(),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}),
			provider.WithFormPostResponseMode(),
			provider.WithAuthPolicies(authutil.Policy()),
		),
		provider.WithRefreshTokenGrant(store, provider.WithRefreshTokenRotation()),
		provider.WithClaims(authutil.Claims...),
		provider.WithACRs(authutil.ACRs...),
		provider.WithClientManager(store),
		provider.WithClientSecretVerifier(oidcstore.VerifyClientSecret),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.SigAlgRS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithErrorHandler(authutil.HandleError),
		provider.WithErrorRenderer(authutil.RenderError()),
		provider.WithDisplayValues(authutil.DisplayValues...),
		provider.WithSubjectIdentifiers(
			[]goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise},
			provider.WithPairwiseSubjectFunc(authutil.PairwiseSubjectFunc()),
		),
		provider.WithLogout(provider.LogoutConfig{
			Manager:    store,
			HandleFunc: authutil.HandleLogout(),
		}, provider.WithLogoutPolicies(authutil.LogoutPolicy()), provider.WithBackChannelLogout()),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", handler)

	server := &http.Server{
		Addr:              ":" + cmp.Or(hostURL.Port(), "443"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{authutil.ServerCert()},
			MinVersion:   tls.VersionTLS12,
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// createClients registers the Applications config.json names: two for the
// client_secret_basic tests and one for client_secret_post. The back-channel
// logout plan gets its own Application (config-backchannel.json): the suite
// fails a test module on a callback it does not expect, so the other plans'
// logouts must not queue a token for them.
func createClients(ctx context.Context, pool *pgxpool.Pool, store *oidcstore.Store) error {
	const cb = "https://localhost.emobix.co.uk:8443/test/a/goidc/"
	apps := []oidcstore.Application{
		{ClientID: "client_one"},
		{ClientID: "client_two"},
		{ClientID: "client_three"},
		{ClientID: "client_backchannel", BackchannelLogoutURI: cb + "backchannel_logout"},
	}
	for _, app := range apps {
		if _, err := store.Client(ctx, app.ClientID); err == nil {
			continue
		} else if !errors.Is(err, goidc.ErrNotFound) {
			return err
		}
		app.Name = app.ClientID
		// 32+ bytes: the suite derives HS256 keys from it.
		app.Secret = app.ClientID + "_secret_0123456789abcdefghijklmnopqrstuvwxyz"
		app.RedirectURIs = []string{cb + "callback"}
		app.PostLogoutRedirectURIs = []string{cb + "post_logout_redirect"}
		if err := oidcstore.CreateApplication(ctx, pool, app); err != nil {
			return err
		}
	}
	return nil
}
