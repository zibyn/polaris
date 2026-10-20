package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidc"
)

const (
	maxResponseByteSize int64 = 1_000_000 // 1 MB.
)

func Client(ctx oidc.Context, id string) (*goidc.Client, error) {
	for _, c := range ctx.StaticClients {
		if c.ID == id {
			return c, nil
		}
	}

	if ctx.ClientManager != nil {
		return ctx.ClientManager.Client(ctx, id)
	}

	return nil, goidc.ErrNotFound
}

type Options struct {
	TrustChain []string
}

func JWKByKeyID(ctx oidc.Context, c *goidc.Client, keyID string) (goidc.JSONWebKey, error) {
	jwks, err := JWKS(ctx, c)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk by key id: %w", err)
	}

	key, err := jwks.Key(keyID)
	if err != nil {
		return goidc.JSONWebKey{}, err
	}
	return key, nil
}

// JWKByAlg returns a client JWK based on the algorithm.
func JWKByAlg(ctx oidc.Context, c *goidc.Client, alg string) (goidc.JSONWebKey, error) {
	jwks, err := JWKS(ctx, c)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk by algorithm: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return goidc.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", alg)
}

// JWKS fetches the client public JWKS using the following priority:
//  1. From jwks_uri.
//  2. Directly from the jwks attribute if present.
//
// It also caches the keys if they are fetched.
func JWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	if jwks := c.CachedJWKS(); jwks != nil {
		return jwks, nil
	}

	if c.JWKSURI != "" {
		jwks, err := fetchJWKS(ctx, c)
		if err != nil {
			return nil, err
		}
		c.CacheJWKS(jwks)
		return jwks, nil
	}

	if c.JWKS == nil {
		return nil, errors.New("the client jwks was informed neither by value nor by reference")
	}
	return c.JWKS, nil
}

func fetchJWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	resp, err := ctx.HTTPClient().Get(c.JWKSURI)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("fetching the client jwks returned status %d", resp.StatusCode))
	}

	if resp.ContentLength > maxResponseByteSize {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("client jwks exceeds max size of %d bytes", maxResponseByteSize),
		)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseByteSize+1)).Decode(&jwks); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata", err)
	}

	return &jwks, nil
}
