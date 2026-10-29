package oidcstore

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/identity"
)

type deviceKey struct{}

type device struct{ ip, userAgent pgtype.Text }

// WithDevice records the client IP and User-Agent of the request ctx serves;
// a Session started or refreshed under ctx remembers them as its device.
func WithDevice(ctx context.Context, ip, userAgent string) context.Context {
	userAgent = identity.UserAgent(userAgent)
	return context.WithValue(ctx, deviceKey{}, device{
		ip:        pgtype.Text{String: ip, Valid: ip != ""},
		userAgent: pgtype.Text{String: userAgent, Valid: userAgent != ""},
	})
}

// Device is what WithDevice recorded in ctx; NULLs if nothing.
func Device(ctx context.Context) (ip, userAgent pgtype.Text) {
	d, _ := ctx.Value(deviceKey{}).(device)
	return d.ip, d.userAgent
}
