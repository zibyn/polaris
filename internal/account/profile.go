package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/profile"
)

// ProfilePath is the direct auth API's 用户资料, for Apps: PATCH sets the
// nickname; PUT and DELETE on ProfilePath + "/avatar" upload and remove the
// avatar.
const ProfilePath = "/v1/auth/profile"

type nicknameInput struct {
	Body struct {
		Nickname string `json:"nickname" doc:"Trimmed; 1–32 characters with no control characters, or empty to clear it"`
	}
}

type profileOutput struct{ Body profile.Profile }

func (s *Service) profileOf(ctx context.Context, sub string) (*profileOutput, error) {
	p, err := s.profiles.Get(ctx, sub)
	return &profileOutput{Body: p}, err
}

func (s *Service) setNickname(ctx context.Context, in *nicknameInput) (*profileOutput, error) {
	sub := callerOf(ctx).sub
	if err := profileErr(s.profiles.SetNickname(ctx, sub, in.Body.Nickname, sub)); err != nil {
		return nil, err
	}
	return s.profileOf(ctx, sub)
}

type avatarInput struct {
	RawBody []byte `contentType:"image/*"`
}

func (s *Service) setAvatar(ctx context.Context, in *avatarInput) (*profileOutput, error) {
	sub := callerOf(ctx).sub
	if err := profileErr(s.profiles.SetAvatar(ctx, sub, bytes.NewReader(in.RawBody), sub)); err != nil {
		return nil, err
	}
	return s.profileOf(ctx, sub)
}

func (s *Service) removeAvatar(ctx context.Context, _ *struct{}) (*profileOutput, error) {
	sub := callerOf(ctx).sub
	if err := s.profiles.RemoveAvatar(ctx, sub, sub); err != nil {
		return nil, err
	}
	return s.profileOf(ctx, sub)
}

// profileErr is 400 for a nickname or an avatar refused.
func profileErr(err error) error {
	var invalid profile.Invalid
	if errors.As(err, &invalid) {
		return huma.Error400BadRequest(invalid.Error())
	}
	return err
}

// registerDirectProfile serves the direct auth API's 用户资料: an App's
// access token changes the User it was issued to, whatever its audience,
// while its Session lives. Each answers with the Profile as it now stands.
// Errors follow RFC 6750, as directDelete's do.
func (s *Service) registerDirectProfile(mux *http.ServeMux) {
	direct := func(change func(r *http.Request, sub string) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			c, err := s.caller(ctx, "", r.Header.Get("Authorization"))
			if err == nil {
				err = change(r, c.sub)
			}
			var p profile.Profile
			if err == nil {
				p, err = s.profiles.Get(ctx, c.sub)
			}
			var invalid profile.Invalid
			switch {
			case err == nil:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(p)
			case errors.Is(err, oidcstore.ErrToken):
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
			case errors.As(err, &invalid):
				status := http.StatusBadRequest
				if errors.Is(err, profile.ErrImageTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": err.Error()})
			default:
				slog.Error("direct profile", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
	mux.HandleFunc("PATCH "+ProfilePath, direct(func(r *http.Request, sub string) error {
		var body struct {
			Nickname *string `json:"nickname"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.Nickname == nil {
			return profile.Invalid("请求体须为 {\"nickname\": \"...\"}")
		}
		return s.profiles.SetNickname(r.Context(), sub, *body.Nickname, sub)
	}))
	mux.HandleFunc("PUT "+ProfilePath+"/avatar", direct(func(r *http.Request, sub string) error {
		return s.profiles.SetAvatar(r.Context(), sub, r.Body, sub)
	}))
	mux.HandleFunc("DELETE "+ProfilePath+"/avatar", direct(func(r *http.Request, sub string) error {
		return s.profiles.RemoveAvatar(r.Context(), sub, sub)
	}))
}
