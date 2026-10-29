// Package profile is the User's 用户资料: a nickname and an avatar (ADR
// 0020). The avatar is re-encoded here, kept in the blob store and served at
// /avatars/{key}. 用户资料 is not identity (ADR 0018): nothing here guards
// how a User signs in.
package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/image/draw"
	"golang.org/x/image/webp"

	"github.com/zibyn/polaris/internal/blob"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Invalid is a nickname or an avatar refused: a 400 with its message.
type Invalid string

func (e Invalid) Error() string { return string(e) }

const (
	ErrNicknameTooLong Invalid = "昵称最多 32 个字符"
	ErrNicknameControl Invalid = "昵称不能含控制字符"
	ErrNotImage        Invalid = "头像须为 JPEG、PNG 或 WebP 图片"
	ErrImageTooLarge   Invalid = "头像不能超过 5 MB"
)

// ErrNoUser is a sub with no User.
var ErrNoUser = errors.New("no such User")

// MaxAvatarBytes is the largest upload taken.
const MaxAvatarBytes = 5 << 20

// size is the side of the square avatar kept.
const size = 512

// maxPixels turns away images that would take too much memory to decode,
// whatever their file size.
const maxPixels = 50_000_000

// keyPrefix keeps avatars apart from other blobs: /avatars/ reads only these.
const keyPrefix = "avatar/"

// CheckNickname trims a nickname and checks it: at most 32 characters, no
// control characters. "" clears it.
func CheckNickname(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 32 {
		return "", ErrNicknameTooLong
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", ErrNicknameControl
	}
	return s, nil
}

// Profile is the User's 用户资料 as Applications see it; empty for unset.
type Profile struct {
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty" doc:"Avatar URL: a 512×512 JPEG; it changes with every upload"`
}

type Store struct {
	issuer string
	pool   *pgxpool.Pool
	q      *sqlc.Queries
}

func New(pool *pgxpool.Pool, issuer string) *Store {
	return &Store{issuer: issuer, pool: pool, q: sqlc.New(pool)}
}

// Get is the User's Profile.
func (s *Store) Get(ctx context.Context, sub string) (Profile, error) {
	r, err := s.q.UserProfile(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNoUser
	}
	return Profile{Nickname: r.Nickname, Picture: s.Picture(r.Avatar)}, err
}

// Picture is the URL of the avatar under key, "" for none.
func (s *Store) Picture(key string) string {
	if key == "" {
		return ""
	}
	return s.issuer + "/avatars/" + strings.TrimPrefix(key, keyPrefix)
}

// SetNickname checks and sets the User's nickname; audited as done by by.
func (s *Store) SetNickname(ctx context.Context, sub, nickname, by string) error {
	nickname, err := CheckNickname(nickname)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.SetNickname(ctx, sqlc.SetNicknameParams{UserID: sub, Nickname: nickname}); err != nil {
			return err
		} else if n == 0 {
			return ErrNoUser
		}
		return audit(ctx, q, "user.profile_updated", sub, by)
	})
}

// SetAvatar takes an uploaded image, crops it to the centre square, and
// keeps it as a 512×512 JPEG (no EXIF) under a new key, deleting the old
// one. Audited as done by by.
func (s *Store) SetAvatar(ctx context.Context, sub string, upload io.Reader, by string) error {
	jpg, err := Avatar(upload)
	if err != nil {
		return err
	}
	key := keyPrefix + rand.Text() // 128 bits
	return s.replaceAvatar(ctx, sub, key, func(store blob.Store) error {
		return store.Put(ctx, key, jpg, "image/jpeg")
	}, "user.avatar_updated", by)
}

// RemoveAvatar deletes the User's avatar; audited as done by by.
func (s *Store) RemoveAvatar(ctx context.Context, sub, by string) error {
	return s.replaceAvatar(ctx, sub, "", func(blob.Store) error { return nil }, "user.avatar_removed", by)
}

func (s *Store) replaceAvatar(ctx context.Context, sub, key string, put func(blob.Store) error, event, by string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		store := blob.NewPG(q)
		old, err := q.LockUserProfile(ctx, sub)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoUser
		} else if err != nil {
			return err
		}
		if err := put(store); err != nil {
			return err
		}
		if _, err := q.SetAvatar(ctx, sqlc.SetAvatarParams{UserID: sub, Avatar: key}); err != nil {
			return err
		}
		if old != "" {
			if err := store.Delete(ctx, old); err != nil {
				return err
			}
		}
		return audit(ctx, q, event, sub, by)
	})
}

// DeleteAvatar deletes the User's avatar blob within q's transaction, for a
// User about to be deleted.
func DeleteAvatar(ctx context.Context, q *sqlc.Queries, sub string) error {
	r, err := q.UserProfile(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && r.Avatar == "" {
		return nil
	} else if err != nil {
		return err
	}
	return blob.NewPG(q).Delete(ctx, r.Avatar)
}

func audit(ctx context.Context, q *sqlc.Queries, event, sub, by string) error {
	detail, _ := json.Marshal(map[string]string{"by": by})
	return q.Audit(ctx, sqlc.AuditParams{Event: event, Sub: pgtype.Text{String: sub, Valid: true}, Detail: detail})
}

// Avatar decodes a JPEG, PNG or WebP image, told apart by its content, and
// returns its centre square as a 512×512 JPEG. Re-encoding drops EXIF and
// anything else that rode along.
func Avatar(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxAvatarBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxAvatarBytes {
		return nil, ErrImageTooLarge
	}
	var decode func(io.Reader) (image.Image, error)
	var config func(io.Reader) (image.Config, error)
	switch http.DetectContentType(raw) {
	case "image/jpeg":
		decode, config = jpeg.Decode, jpeg.DecodeConfig
	case "image/png":
		decode, config = png.Decode, png.DecodeConfig
	case "image/webp":
		decode, config = webp.Decode, webp.DecodeConfig
	default:
		return nil, ErrNotImage
	}
	if c, err := config(bytes.NewReader(raw)); err != nil || c.Width < 1 || c.Height < 1 || c.Width*c.Height > maxPixels {
		return nil, ErrNotImage
	}
	img, err := decode(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrNotImage
	}
	b := img.Bounds()
	side := min(b.Dx(), b.Dy())
	x, y := b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, image.Rect(x, y, x+side, y+side), draw.Src, nil)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Register serves the avatars at /avatars/{key}: public, cached for good
// (a new upload is a new key).
func (s *Store) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /avatars/{key}", func(w http.ResponseWriter, r *http.Request) {
		b, contentType, err := blob.NewPG(s.q).Get(r.Context(), keyPrefix+r.PathValue("key"))
		if errors.Is(err, blob.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	})
}
