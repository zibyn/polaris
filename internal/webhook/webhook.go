// Package webhook delivers User events (user.deleted, user.disabled,
// user.enabled, user.updated) to the Applications that set up a webhook
// (docs/spec/protocol.md#webhook), signed the Standard Webhooks way with each
// Application's key, and logout tokens to the Applications with a
// back-channel logout URI (OIDC Back-Channel Logout 1.0); it retries
// failures with backoff.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidcstore"
)

const (
	// Waits double from a minute up to 12 hours; the 12th failure, about a
	// day in, drops the delivery.
	maxAttempts = 12
	maxWait     = 12 * time.Hour
	// A claimed delivery is held back this long while it is being sent, so
	// that no other replica sends it too; batch is how many one claims.
	hold  = 5 * time.Minute
	batch = 20
)

type Sender struct {
	q       *sqlc.Queries
	keyring *crypt.Keyring
	keys    *oidcstore.Keys
	issuer  string
	client  *http.Client
}

// New makes a Sender; issuer signs the logout tokens.
func New(pool *pgxpool.Pool, keyring *crypt.Keyring, issuer string) *Sender {
	return &Sender{q: sqlc.New(pool), keyring: keyring, keys: oidcstore.NewKeys(pool, keyring), issuer: issuer,
		client: &http.Client{Timeout: 10 * time.Second}}
}

// Run delivers what is due every 10 seconds until ctx ends.
func (s *Sender) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Deliver(ctx); err != nil {
				slog.Error("webhook", "err", err)
			}
		}
	}
}

// Deliver sends the deliveries that are due, once each.
func (s *Sender) Deliver(ctx context.Context) error {
	due, err := s.q.ClaimDeliveries(ctx, sqlc.ClaimDeliveriesParams{HoldSecs: int32(hold.Seconds()), Batch: batch})
	if err != nil {
		return err
	}
	for _, d := range due {
		if d.Url == "" { // the webhook was turned off since
			err = s.q.DeleteDelivery(ctx, d.ID)
		} else if sendErr := s.send(ctx, d); sendErr == nil {
			err = s.q.DeleteDelivery(ctx, d.ID)
		} else if d.Attempts >= maxAttempts {
			slog.Warn("webhook dropped", "client_id", d.ClientID, "id", d.ID, "err", sendErr)
			err = s.drop(ctx, d)
		} else {
			wait := min(time.Minute<<(d.Attempts-1), maxWait)
			err = s.q.RetryDelivery(ctx, sqlc.RetryDeliveryParams{ID: d.ID, WaitSecs: int32(wait.Seconds())})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Sender) send(ctx context.Context, d sqlc.ClaimDeliveriesRow) error {
	req, err := s.request(ctx, d)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func (s *Sender) request(ctx context.Context, d sqlc.ClaimDeliveriesRow) (*http.Request, error) {
	if d.Kind == "logout" {
		var p struct{ Sub, Sid string }
		if err := json.Unmarshal(d.Payload, &p); err != nil {
			return nil, err
		}
		token, err := s.keys.LogoutToken(ctx, s.issuer, d.ClientID, p.Sub, p.Sid)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Url, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}
	secret, err := s.keyring.Open(d.Secret, []byte("application:"+d.ClientID+":webhook"))
	if err != nil {
		return nil, err
	}
	body, err := eventBody(d)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", d.ID)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sign(secret, d.ID, ts, body))
	return req, nil
}

// facts are what a delivery keeps of a User event (and the sub of a logout).
type facts struct {
	Type    string   `json:"type"`
	Sub     string   `json:"sub"`
	Changed []string `json:"changed"`
}

// eventBody is the webhook's JSON (docs/spec/protocol.md#webhook), the same
// bytes on every attempt: the event's facts and when it happened.
func eventBody(d sqlc.ClaimDeliveriesRow) ([]byte, error) {
	var f facts
	if err := json.Unmarshal(d.Payload, &f); err != nil {
		return nil, err
	}
	type data struct {
		Sub     string   `json:"sub"`
		Changed []string `json:"changed,omitempty"`
	}
	return json.Marshal(struct {
		Type      string `json:"type"`
		Timestamp string `json:"timestamp"`
		Data      data   `json:"data"`
	}{f.Type, d.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z"), data{f.Sub, f.Changed}})
}

// sign makes a Standard Webhooks signature. A "whsec_" key is base64 after
// the prefix, as the Standard Webhooks libraries expect; any other key is
// used as its bytes.
func sign(secret []byte, id, ts string, body []byte) string {
	if k, ok := bytes.CutPrefix(secret, []byte("whsec_")); ok {
		if raw, err := base64.StdEncoding.DecodeString(string(k)); err == nil {
			secret = raw
		}
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// drop gives up on a delivery, audited so that admins see which
// Application missed which User's event or logout.
func (s *Sender) drop(ctx context.Context, d sqlc.ClaimDeliveriesRow) error {
	var f facts // a logout token's has its sub too
	_ = json.Unmarshal(d.Payload, &f)
	detail, _ := json.Marshal(map[string]string{"application": d.ClientID, "id": d.ID, "kind": d.Kind})
	sub := f.Sub
	if err := s.q.Audit(ctx, sqlc.AuditParams{Event: "webhook.failed", Sub: pgtype.Text{String: sub, Valid: true}, Detail: detail}); err != nil {
		return err
	}
	return s.q.DeleteDelivery(ctx, d.ID)
}
