package oidcstore

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
)

// maxUserAgent is how much of a User-Agent a Session keeps, in bytes.
const maxUserAgent = 512

type deviceKey struct{}

type device struct{ ip, userAgent pgtype.Text }

// WithDevice records the client IP and User-Agent of the request ctx serves;
// a Session started or refreshed under ctx remembers them as its device.
func WithDevice(ctx context.Context, ip, userAgent string) context.Context {
	if len(userAgent) > maxUserAgent {
		userAgent = userAgent[:maxUserAgent]
	}
	// Valid UTF-8 for a text column, a rune cut in half included.
	userAgent = strings.ToValidUTF8(userAgent, "")
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
