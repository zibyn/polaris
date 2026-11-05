package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Each optimistic write (ADR 0030) goes through with what it read still
// current, and touches no row once another write changed it: that zero is
// the conflict its caller retries on.
func TestOptimisticWritesRefuseStaleReads(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	type write struct {
		name string
		run  func() (int64, error)
		want int64
	}
	settings := func(current string) func() (int64, error) {
		return func() (int64, error) {
			return q.UpdateSettings(ctx, sqlc.UpdateSettingsParams{ByID: "ADMIN", ByType: "user", PasswordLogin: "on",
				DailySendLimit: 1000, AuditRetentionDays: 180, PasskeyLogin: true, CurrentLogo: current})
		}
	}
	application := func(current string) func() (int64, error) {
		return func() (int64, error) {
			return q.UpdateApplication(ctx, sqlc.UpdateApplicationParams{ClientID: "app", Name: "app", RedirectUris: []string{},
				PostLogoutRedirectUris: []string{}, AppleAppIds: []string{}, AndroidApps: []byte("[]"), CurrentLogo: current})
		}
	}
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertProvider(ctx, sqlc.InsertProviderParams{ID: "gh", Type: "github", Name: "GitHub", Config: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertApplication(ctx, sqlc.InsertApplicationParams{ClientID: "app", Type: "public"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BeginTOTP(ctx, sqlc.BeginTOTPParams{UserID: "ALICE", Secret: []byte("s1")}); err != nil {
		t.Fatal(err)
	}
	logo := func(key string) func() (int64, error) {
		return func() (int64, error) {
			return 1, q.SetInstanceLogo(ctx, sqlc.SetInstanceLogoParams{ByID: "ADMIN", ByType: "user", Logo: key})
		}
	}
	for _, w := range []write{
		{"first save of a Channel", func() (int64, error) {
			return q.SaveChannel(ctx, sqlc.SaveChannelParams{Kind: "email", Plugin: "smtp", Config: []byte("{}"), Version: 0})
		}, 1},
		{"a second first save", func() (int64, error) {
			return q.SaveChannel(ctx, sqlc.SaveChannelParams{Kind: "email", Plugin: "smtp", Config: []byte("{}"), Version: 0})
		}, 0},
		{"Channel save at version 1", func() (int64, error) {
			return q.SaveChannel(ctx, sqlc.SaveChannelParams{Kind: "email", Plugin: "smtp", Config: []byte("{}"), Version: 1})
		}, 1},
		{"Channel save at version 1 again", func() (int64, error) {
			return q.SaveChannel(ctx, sqlc.SaveChannelParams{Kind: "email", Plugin: "smtp", Config: []byte("{}"), Version: 1})
		}, 0},

		{"Provider save at version 1", func() (int64, error) {
			return q.UpdateProvider(ctx, sqlc.UpdateProviderParams{ID: "gh", Name: "GH", Config: []byte("{}"), Version: 1})
		}, 1},
		{"Provider save at version 1 again", func() (int64, error) {
			return q.UpdateProvider(ctx, sqlc.UpdateProviderParams{ID: "gh", Name: "GH", Config: []byte("{}"), Version: 1})
		}, 0},

		{"avatar replacing none", func() (int64, error) {
			return q.SetAvatar(ctx, sqlc.SetAvatarParams{UserID: "ALICE", Avatar: "avatar/a", Old: ""})
		}, 1},
		{"avatar replacing none, again", func() (int64, error) {
			return q.SetAvatar(ctx, sqlc.SetAvatarParams{UserID: "ALICE", Avatar: "avatar/b", Old: ""})
		}, 0},

		{"settings with the Logo read", settings(""), 1},
		{"an upload replaces the Logo", logo("brand/x"), 1},
		{"settings with the Logo read before it", settings(""), 0},
		{"settings with the new Logo", settings("brand/x"), 1},

		{"Application with the Logo read", application(""), 1},
		{"an upload replaces its Logo", func() (int64, error) {
			return q.SetApplicationLogo(ctx, sqlc.SetApplicationLogoParams{ClientID: "app", Logo: pgtype.Text{String: "brand/y", Valid: true}})
		}, 1},
		{"Application with the Logo read before it", application(""), 0},

		{"setup token made", func() (int64, error) { return q.SetSetupToken(ctx, []byte("t1")) }, 1},
		{"a second setup token", func() (int64, error) { return q.SetSetupToken(ctx, []byte("t2")) }, 0},
		{"setup closed", func() (int64, error) { return q.CloseSetup(ctx) }, 1},
		{"setup closed again", func() (int64, error) { return q.CloseSetup(ctx) }, 0},

		{"TOTP confirmed against another secret", func() (int64, error) {
			return q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: "ALICE", Step: 5, Secret: []byte("s0")})
		}, 0},
		{"TOTP confirmed", func() (int64, error) {
			return q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: "ALICE", Step: 5, Secret: []byte("s1")})
		}, 1},
		{"TOTP confirmed again", func() (int64, error) {
			return q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: "ALICE", Step: 6, Secret: []byte("s1")})
		}, 0},
		{"kept on while on", func() (int64, error) { return q.KeepTOTPOn(ctx, "ALICE") }, 1},
		{"turned off", func() (int64, error) { return q.DeleteTOTP(ctx, "ALICE") }, 1},
		{"kept on once off", func() (int64, error) { return q.KeepTOTPOn(ctx, "ALICE") }, 0},
		{"turned off again", func() (int64, error) { return q.DeleteTOTP(ctx, "ALICE") }, 0},
	} {
		if n, err := w.run(); err != nil || n != w.want {
			t.Errorf("%s: %d rows, %v; want %d", w.name, n, err, w.want)
		}
	}
}
