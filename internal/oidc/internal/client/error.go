package client

import "github.com/zibyn/polaris/internal/oidc/goidc"

var ErrClientNotIdentified = goidc.NewError(goidc.ErrorCodeInvalidClient, "could not identify the client")
