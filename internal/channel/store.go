package channel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

// ErrNotConfigured: no Channel is enabled for that Identifier kind.
var ErrNotConfigured = errors.New("channel not configured")

// Store keeps the enabled Channel of each Identifier kind in PG.
type Store struct {
	pool    *pgxpool.Pool
	keyring *crypt.Keyring
}

func NewStore(pool *pgxpool.Pool, keyring *crypt.Keyring) *Store {
	return &Store{pool: pool, keyring: keyring}
}

// Settings are a kind's Channel as an admin may read them: secret fields
// show only when they were last set.
type Settings struct {
	Kind      string               `json:"kind" enum:"phone,email"`
	Plugin    string               `json:"plugin"`
	Config    map[string]string    `json:"config" doc:"Fields that are not secret"`
	Secrets   map[string]time.Time `json:"secrets" doc:"When each secret field was last set"`
	UpdatedAt time.Time            `json:"updatedAt"`
}

func (s *Store) List(ctx context.Context) ([]Settings, error) {
	rows, err := sqlc.New(s.pool).ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	out := []Settings{}
	for _, r := range rows {
		c := Settings{Kind: r.Kind, Plugin: r.Plugin, UpdatedAt: r.UpdatedAt.Time}
		if err := json.Unmarshal(r.Config, &c.Config); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(r.Secrets, &c.Secrets); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Put enables plugin for kind with config. An empty secret field keeps the
// stored value, so the console never needs to read secrets back; switching
// plugin drops the old plugin's secrets. Audited as done by by.
func (s *Store) Put(ctx context.Context, kind, plugin string, config map[string]string, by string) error {
	p := Get(plugin)
	if p == nil {
		return identity.Invalid("没有这个 Channel 插件:" + plugin)
	}
	if !slices.Contains(p.Kinds, kind) {
		return identity.Invalid(p.Name + " 不能投递到这类 Identifier")
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := sqlc.New(tx)
		if err := q.LockChannels(ctx); err != nil {
			return err
		}
		var old string
		if r, err := q.GetChannel(ctx, kind); err == nil {
			old = r.Plugin
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		stored := map[string]string{}
		if old == plugin {
			var err error
			if stored, err = s.secrets(ctx, q, kind, plugin); err != nil {
				return err
			}
		} else if err := q.DeleteChannelSecrets(ctx, kind); err != nil {
			return err
		}

		plain, full, fresh := map[string]string{}, map[string]string{}, map[string]string{}
		for _, f := range p.Fields {
			v := strings.TrimSpace(config[f.Key])
			switch {
			case f.Secret && v != "":
				fresh[f.Key] = v
			case f.Secret:
				v = stored[f.Key]
			default:
				plain[f.Key] = v
			}
			if v == "" {
				if !f.Optional {
					return identity.Invalid(f.Label + " 必填")
				}
				continue
			}
			if err := f.Check(v); err != nil {
				return err
			}
			full[f.Key] = v
		}
		if _, err := p.New(full); err != nil {
			return identity.Invalid(err.Error())
		}

		js, err := json.Marshal(plain)
		if err != nil {
			return err
		}
		if err := q.PutChannel(ctx, sqlc.PutChannelParams{Kind: kind, Plugin: plugin, Config: js}); err != nil {
			return err
		}
		for k, v := range fresh {
			sealed, err := s.keyring.Seal([]byte(v), aad(kind, plugin, k))
			if err != nil {
				return err
			}
			if err := q.PutChannelSecret(ctx, sqlc.PutChannelSecretParams{Kind: kind, Field: k, Value: sealed}); err != nil {
				return err
			}
		}
		detail, _ := json.Marshal(map[string]string{"kind": kind, "by": by})
		return q.Audit(ctx, sqlc.AuditParams{Event: "channel.saved", Detail: detail})
	})
}

// Check tells the admin what is wrong with v as f's value, if anything.
func (f Field) Check(v string) error {
	switch f.Type {
	case "number":
		if _, err := strconv.Atoi(v); err != nil {
			return identity.Invalid(f.Label + " 须为整数")
		}
	case "url":
		if u, err := url.Parse(v); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return identity.Invalid(f.Label + " 须为 http(s) URL")
		}
	}
	return nil
}

// Delete turns off codes of kind, audited as done by by.
func (s *Store) Delete(ctx context.Context, kind, by string) error {
	return sqlc.New(s.pool).DeleteChannel(ctx, sqlc.DeleteChannelParams{Kind: kind, By: by})
}

// Channel returns the enabled Channel for kind, or ErrNotConfigured.
// ponytail: reads PG on every send; cache for a few seconds if sends get busy.
func (s *Store) Channel(ctx context.Context, kind string) (Channel, error) {
	q := sqlc.New(s.pool)
	r, err := q.GetChannel(ctx, kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotConfigured
	} else if err != nil {
		return nil, err
	}
	p := Get(r.Plugin)
	if p == nil {
		return nil, fmt.Errorf("channel plugin %q is not in this build", r.Plugin)
	}
	config, err := s.secrets(ctx, q, kind, r.Plugin)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return nil, err
	}
	return p.New(config)
}

// secrets opens kind's stored secret fields.
func (s *Store) secrets(ctx context.Context, q *sqlc.Queries, kind, plugin string) (map[string]string, error) {
	rows, err := q.ChannelSecrets(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		v, err := s.keyring.Open(r.Value, aad(kind, plugin, r.Field))
		if err != nil {
			return nil, err
		}
		out[r.Field] = string(v)
	}
	return out, nil
}

func aad(kind, plugin, field string) []byte {
	return []byte("channel:" + kind + ":" + plugin + ":" + field)
}
