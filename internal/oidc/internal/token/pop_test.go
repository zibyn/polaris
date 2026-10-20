package token

import (
	"errors"
	"testing"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/oidctest"
)

func TestValidatePoP_NoConfirmation(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{}

	// When.
	err := ValidatePoP(ctx, "random_token", cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateDPoP_NoThumbprint(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{}

	// When.
	err := validateDPoP(ctx, "random_token", cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateDPoP_MissingHeader(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{
		JWKThumbprint: "random_thumbprint",
	}

	// When.
	err := validateDPoP(ctx, "random_token", cnf)

	// Then.
	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}

func TestValidateDPoP_DisabledButBound(t *testing.T) {
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{
		JWKThumbprint: "bound_thumbprint",
	}

	err := validateDPoP(ctx, "random_token", cnf)

	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}
