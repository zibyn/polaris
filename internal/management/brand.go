package management

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/blob"
	"github.com/zibyn/polaris/internal/brand"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Brand is a 品牌 (ADR 0028): the instance's, or an Application's items
// overriding it. Every item is optional; on an Application one left out
// follows the instance.
type Brand struct {
	Name  string `json:"name,omitempty" maxLength:"64" doc:"Replaces 「Polaris」 in the brand panel and the page title"`
	Logo  string `json:"logo,omitempty" doc:"The Logo, as the upload operation returned it; served at /brand-logos/{logo}. Only the Logo already uploaded here may be sent back; empty removes it"`
	Color string `json:"color,omitempty" doc:"Primary colour as #rrggbb; white text on it must reach 4.5:1 (WCAG AA). Buttons, links and focus rings take it, with derived hover and tint shades"`
}

// check makes b what is stored, or refuses it; logo is the Logo stored now.
func (b *Brand) check(logo string) error {
	b.Name = strings.TrimSpace(b.Name)
	if b.Color != "" {
		c, err := brand.CheckColor(b.Color)
		if err != nil {
			return err
		}
		b.Color = c
	}
	if b.Logo != "" && b.Logo != logo {
		return brand.ErrLogoUnknown
	}
	return nil
}

// logoKey is the blob key of the Logo reference ref.
func logoKey(ref string) string {
	if ref == "" {
		return ""
	}
	return brand.KeyPrefix + ref
}

func logoRef(key string) string { return strings.TrimPrefix(key, brand.KeyPrefix) }

// nullable is s, NULL when empty: an item that follows the instance.
func nullable(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

// brandOf is an Application's own items, nil when it follows the instance
// in all.
func brandOf(name, logo, color pgtype.Text) *Brand {
	if !name.Valid && !logo.Valid && !color.Valid {
		return nil
	}
	return &Brand{Name: name.String, Logo: logoRef(logo.String), Color: color.String}
}

type logoInput struct {
	RawBody []byte `contentType:"image/*"`
}

type logoOutput struct {
	Body struct {
		Logo string `json:"logo" doc:"The Logo's reference; served at /brand-logos/{logo}"`
	}
}

// putLogo stores an uploaded Logo and has set point at it, in one
// transaction that also deletes the Logo it replaced.
func (s *Service) putLogo(ctx context.Context, raw []byte, set func(*sqlc.Queries, string) error) (*logoOutput, error) {
	contentType, err := brand.LogoType(raw)
	if err != nil {
		return nil, invalid(err)
	}
	ref := rand.Text() // 128 bits
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := blob.NewPG(q).Put(ctx, logoKey(ref), raw, contentType); err != nil {
			return err
		}
		if err := set(q, logoKey(ref)); err != nil {
			return err
		}
		return q.DeleteUnusedLogos(ctx)
	})
	if err != nil {
		return nil, err
	}
	out := &logoOutput{}
	out.Body.Logo = ref
	return out, nil
}

func (s *Service) setInstanceLogo(ctx context.Context, in *logoInput) (*logoOutput, error) {
	return s.putLogo(ctx, in.RawBody, func(q *sqlc.Queries, key string) error {
		return q.SetInstanceLogo(ctx, sqlc.SetInstanceLogoParams{Logo: key, By: callerSub(ctx)})
	})
}

func (s *Service) removeInstanceLogo(ctx context.Context, _ *struct{}) (*struct{}, error) {
	return nil, pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.SetInstanceLogo(ctx, sqlc.SetInstanceLogoParams{By: callerSub(ctx)}); err != nil {
			return err
		}
		return q.DeleteUnusedLogos(ctx)
	})
}

// brandable is an Application that may have a 品牌 of its own, or why not.
func (s *Service) brandable(ctx context.Context, clientID string) error {
	app, err := s.application(ctx, clientID)
	if err != nil {
		return err
	}
	return invalid(noOwn(app.Builtin, app.Type, "品牌"))
}

type appLogoInput struct {
	ClientID string `path:"clientId"`
	RawBody  []byte `contentType:"image/*"`
}

func (s *Service) setApplicationLogo(ctx context.Context, in *appLogoInput) (*logoOutput, error) {
	if err := s.brandable(ctx, in.ClientID); err != nil {
		return nil, err
	}
	return s.putLogo(ctx, in.RawBody, func(q *sqlc.Queries, key string) error {
		return s.setAppLogo(ctx, q, in.ClientID, key)
	})
}

func (s *Service) removeApplicationLogo(ctx context.Context, in *clientIDPath) (*struct{}, error) {
	if err := s.brandable(ctx, in.ClientID); err != nil {
		return nil, err
	}
	return nil, pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := s.setAppLogo(ctx, q, in.ClientID, ""); err != nil {
			return err
		}
		return q.DeleteUnusedLogos(ctx)
	})
}

func (s *Service) setAppLogo(ctx context.Context, q *sqlc.Queries, clientID, key string) error {
	if n, err := q.SetApplicationLogo(ctx, sqlc.SetApplicationLogoParams{ClientID: clientID, Logo: nullable(key)}); err != nil {
		return err
	} else if n == 0 { // deleted meanwhile
		return errNoApplication
	}
	return auditApplication(ctx, q, "application.updated", clientID)
}

// registerBrand adds the Logo uploads and removals.
func (s *Service) registerBrand(api huma.API) {
	huma.Register(api, logoOp("set-instance-logo", "config:write", "/settings/brand/logo",
		"Upload the instance's Logo: a PNG, WebP or SVG of at most 1 MB, judged by its bytes and kept as sent; 422 for what is not one"), s.setInstanceLogo)
	op(api, http.MethodDelete, "remove-instance-logo", "config:write", "/settings/brand/logo", "Remove the instance's Logo", s.removeInstanceLogo)
	huma.Register(api, logoOp("set-application-logo", "applications:write", "/applications/{clientId}/brand/logo",
		"Upload an Application's own Logo, as the instance's; not for the built-in or M2M Applications"), s.setApplicationLogo)
	op(api, http.MethodDelete, "remove-application-logo", "applications:write", "/applications/{clientId}/brand/logo", "Remove an Application's own Logo: it follows the instance's", s.removeApplicationLogo)
}

// logoOp is a Logo upload: raw bytes, a body past 1 MB a 422 like any other
// Logo refused.
func logoOp(id, permission, path, summary string) huma.Operation {
	return huma.Operation{
		OperationID: id, Method: http.MethodPut, Path: path, Summary: summary, Description: describe(permission),
		Errors:       []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity},
		Metadata:     map[string]any{"permission": permission},
		MaxBodyBytes: 2 * brand.MaxLogoBytes, // past the limit, so that LogoType says why
	}
}
