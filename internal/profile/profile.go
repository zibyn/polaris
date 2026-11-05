// Package profile is the User's 用户资料: a nickname, an avatar (ADR 0020)
// and the other OIDC standard profile and address claims (ADR 0029). The avatar is re-encoded here, kept in the blob store and served at
// /avatars/{key}. 用户资料 is not identity (ADR 0018): nothing here guards
// how a User signs in.
package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // zoneinfo is checked against it wherever Polaris runs
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/image/draw"
	"golang.org/x/image/webp"
	"golang.org/x/text/language"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/blob"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Invalid is a nickname or an avatar refused: a 400 with its message.
type Invalid string

func (e Invalid) Error() string { return string(e) }

const (
	ErrNotImage      Invalid = "头像须为 JPEG、PNG 或 WebP 图片"
	ErrImageTooLarge Invalid = "头像不能超过 5 MB"
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
func CheckNickname(s string) (string, error) { return checkText("昵称", s, 32, false) }

// checkText trims s and checks it: at most max characters, no control
// characters but, when multiline, line breaks (kept as \n).
func checkText(label, s string, max int, multiline bool) (string, error) {
	s = strings.TrimSpace(s)
	if multiline {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	if utf8.RuneCountInString(s) > max {
		return "", Invalid(fmt.Sprintf("%s最多 %d 个字符", label, max))
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && !(multiline && r == '\n') }) >= 0 {
		return "", Invalid(label + "不能含控制字符")
	}
	return s, nil
}

// Address is the address claim (OIDC Core 5.1.1); empty for unset.
type Address struct {
	Formatted     string `json:"formatted,omitempty" doc:"The full address to display; may hold line breaks"`
	StreetAddress string `json:"street_address,omitempty" doc:"Street, house number, apartment; may hold line breaks"`
	Locality      string `json:"locality,omitempty" doc:"City"`
	Region        string `json:"region,omitempty" doc:"State, province or prefecture"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty" doc:"Country name or code"`
}

// Claims are the standard claims kept as they are sent: every profile claim
// but nickname, picture, preferred_username and updated_at, plus address.
type Claims struct {
	Name       string   `json:"name,omitempty" doc:"Full name, as the User wants it shown"`
	GivenName  string   `json:"given_name,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	MiddleName string   `json:"middle_name,omitempty"`
	Profile    string   `json:"profile,omitempty" doc:"Profile page URL, http(s)"`
	Website    string   `json:"website,omitempty" doc:"Web page or blog URL, http(s)"`
	Gender     string   `json:"gender,omitempty" doc:"female, male, or anything else the User says"`
	Birthdate  string   `json:"birthdate,omitempty" doc:"YYYY-MM-DD, 0000-MM-DD without the year, or YYYY alone"`
	Zoneinfo   string   `json:"zoneinfo,omitempty" doc:"IANA time zone, such as Asia/Shanghai"`
	Locale     string   `json:"locale,omitempty" doc:"BCP 47 language tag, such as zh-CN"`
	Address    *Address `json:"address,omitempty"`
}

// Profile is the User's 用户资料 as Applications see it, named as the OIDC
// claims are; empty for unset.
type Profile struct {
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty" doc:"Avatar URL: a 512×512 JPEG; it changes with every upload"`
	Claims
	UpdatedAt int64 `json:"updated_at,omitempty" doc:"When 用户资料 last changed, in Unix seconds; absent if it never has"`
}

// Patch changes 用户资料: a field left out stays, "" clears it.
type Patch struct {
	Nickname   *string  `json:"nickname,omitempty" doc:"Trimmed; at most 32 characters with no control characters"`
	Name       *string  `json:"name,omitempty" doc:"At most 64 characters"`
	GivenName  *string  `json:"given_name,omitempty" doc:"At most 64 characters"`
	FamilyName *string  `json:"family_name,omitempty" doc:"At most 64 characters"`
	MiddleName *string  `json:"middle_name,omitempty" doc:"At most 64 characters"`
	Profile    *string  `json:"profile,omitempty" doc:"http(s) URL"`
	Website    *string  `json:"website,omitempty" doc:"http(s) URL"`
	Gender     *string  `json:"gender,omitempty" doc:"female, male, or anything else; at most 32 characters"`
	Birthdate  *string  `json:"birthdate,omitempty" doc:"YYYY-MM-DD, 0000-MM-DD or YYYY"`
	Zoneinfo   *string  `json:"zoneinfo,omitempty" doc:"IANA time zone"`
	Locale     *string  `json:"locale,omitempty" doc:"BCP 47 language tag"`
	Address    *Address `json:"address,omitempty" doc:"Replaces the whole address; {} clears it"`
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
	} else if err != nil {
		return Profile{}, err
	}
	p := Profile{Nickname: r.Nickname, Picture: s.Picture(r.Avatar)}
	if r.ProfileUpdatedAt.Valid {
		p.UpdatedAt = r.ProfileUpdatedAt.Time.Unix()
	}
	return p, json.Unmarshal(r.Profile, &p.Claims)
}

// Picture is the URL of the avatar under key, "" for none.
func (s *Store) Picture(key string) string {
	if key == "" {
		return ""
	}
	return s.issuer + "/avatars/" + strings.TrimPrefix(key, keyPrefix)
}

// Update checks p and applies it; audited as done by by.
func (s *Store) Update(ctx context.Context, sub string, p Patch, by audit.Actor) error {
	arg, err := p.params()
	if err != nil {
		return err
	}
	arg.UserID = sub
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.SetProfile(ctx, arg); err != nil {
			return err
		} else if n == 0 {
			return ErrNoUser
		}
		return writeAudit(ctx, q, "user.profile_updated", sub, by)
	})
}

// params checks every field p sets and sorts them into the claims to set
// and the ones to clear.
func (p Patch) params() (sqlc.SetProfileParams, error) {
	arg := sqlc.SetProfileParams{Clear: []string{}}
	if p.Nickname != nil {
		n, err := CheckNickname(*p.Nickname)
		if err != nil {
			return arg, err
		}
		arg.SetNickname, arg.Nickname = true, n
	}
	set := map[string]any{}
	put := func(key string, v any, empty bool) {
		if empty {
			arg.Clear = append(arg.Clear, key)
		} else {
			set[key] = v
		}
	}
	for _, f := range []struct {
		key, label string
		v          *string
		check      func(label, s string) (string, error)
	}{
		{"name", "姓名", p.Name, text(64)},
		{"given_name", "名", p.GivenName, text(64)},
		{"family_name", "姓", p.FamilyName, text(64)},
		{"middle_name", "中间名", p.MiddleName, text(64)},
		{"profile", "个人主页", p.Profile, checkURL},
		{"website", "网站", p.Website, checkURL},
		{"gender", "性别", p.Gender, text(32)},
		{"birthdate", "生日", p.Birthdate, checkBirthdate},
		{"zoneinfo", "时区", p.Zoneinfo, checkZoneinfo},
		{"locale", "语言", p.Locale, checkLocale},
	} {
		if f.v == nil {
			continue
		}
		v, err := f.check(f.label, *f.v)
		if err != nil {
			return arg, err
		}
		put(f.key, v, v == "")
	}
	if a := p.Address; a != nil {
		var err error
		for _, f := range []struct {
			label     string
			v         *string
			max       int
			multiline bool
		}{
			{"完整地址", &a.Formatted, 256, true},
			{"街道地址", &a.StreetAddress, 256, true},
			{"城市", &a.Locality, 64, false},
			{"省/州", &a.Region, 64, false},
			{"邮编", &a.PostalCode, 16, false},
			{"国家/地区", &a.Country, 64, false},
		} {
			if *f.v, err = checkText(f.label, *f.v, f.max, f.multiline); err != nil {
				return arg, err
			}
		}
		put("address", a, *a == Address{})
	}
	var err error
	arg.Set, err = json.Marshal(set)
	return arg, err
}

func text(max int) func(label, s string) (string, error) {
	return func(label, s string) (string, error) { return checkText(label, s, max, false) }
}

// checkURL takes an absolute http(s) URL: Applications show it as a link.
func checkURL(label, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(s) > 2048 ||
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", Invalid(label + "须为 http(s) 地址")
	}
	return s, nil
}

// checkBirthdate takes YYYY-MM-DD, 0000-MM-DD (the year withheld) or YYYY
// (the year alone), as OIDC Core 5.1 has it.
func checkBirthdate(label, s string) (string, error) {
	s = strings.TrimSpace(s)
	bad := Invalid(label + "须为 YYYY-MM-DD、0000-MM-DD 或 YYYY")
	switch {
	case s == "":
		return "", nil
	case len(s) == 4:
		if _, err := time.Parse("2006", s); err != nil || s == "0000" {
			return "", bad
		}
	case len(s) == 10:
		// 2000 is a leap year, so 0000-02-29 passes.
		if _, err := time.Parse(time.DateOnly, strings.Replace(s, "0000-", "2000-", 1)); err != nil {
			return "", bad
		}
	default:
		return "", bad
	}
	return s, nil
}

func checkZoneinfo(label, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if _, err := time.LoadLocation(s); err != nil || s == "Local" {
		return "", Invalid(label + "须为 IANA 时区,如 Asia/Shanghai")
	}
	return s, nil
}

// checkLocale takes a BCP 47 tag and keeps it in its canonical form.
func checkLocale(label, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	tag, err := language.Parse(s)
	if err != nil || tag == language.Und {
		return "", Invalid(label + "须为 BCP 47 语言标签,如 zh-CN")
	}
	return tag.String(), nil
}

// SetAvatar takes an uploaded image, crops it to the centre square, and
// keeps it as a 512×512 JPEG (no EXIF) under a new key, deleting the old
// one. Audited as done by by.
func (s *Store) SetAvatar(ctx context.Context, sub string, upload io.Reader, by audit.Actor) error {
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
func (s *Store) RemoveAvatar(ctx context.Context, sub string, by audit.Actor) error {
	return s.replaceAvatar(ctx, sub, "", func(blob.Store) error { return nil }, "user.avatar_removed", by)
}

func (s *Store) replaceAvatar(ctx context.Context, sub, key string, put func(blob.Store) error, event string, by audit.Actor) error {
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
		return writeAudit(ctx, q, event, sub, by)
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

func writeAudit(ctx context.Context, q *sqlc.Queries, event, sub string, by audit.Actor) error {
	detail := by.Detail(nil)
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
