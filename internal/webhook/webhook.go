// Package webhook delivers User events (user.deleted, user.disabled,
// user.enabled, user.updated) to the Applications that set up a webhook
// (docs/spec/protocol.md#webhook), signed the Standard Webhooks way
// with each Application's key, and retries failures with backoff.
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
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

const (
	// Waits double from a minute up to 12 hours; the 12th failure, about a
	// day in, drops the delivery.
	maxAttempts = 12
	maxWait     = 12 * time.Hour
)

type Sender struct {
	q       *sqlc.Queries
	keyring *crypt.Keyring
	client  *http.Client
}

func New(pool *pgxpool.Pool, keyring *crypt.Keyring) *Sender {
	return &Sender{q: sqlc.New(pool), keyring: keyring, client: &http.Client{Timeout: 10 * time.Second}}
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
	due, err := s.q.ClaimDeliveries(ctx)
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
	secret, err := s.keyring.Open(d.Secret, []byte("application:"+d.ClientID+":webhook"))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Url, bytes.NewReader(d.Payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", d.ID)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sign(secret, d.ID, ts, d.Payload))
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
// Application missed which deleted User.
func (s *Sender) drop(ctx context.Context, d sqlc.ClaimDeliveriesRow) error {
	var p struct {
		Data struct {
			Sub string `json:"sub"`
		} `json:"data"`
	}
	_ = json.Unmarshal(d.Payload, &p)
	detail, _ := json.Marshal(map[string]string{"application": d.ClientID, "id": d.ID})
	if err := s.q.Audit(ctx, sqlc.AuditParams{Event: "webhook.failed", Sub: pgtype.Text{String: p.Data.Sub, Valid: true}, Detail: detail}); err != nil {
		return err
	}
	return s.q.DeleteDelivery(ctx, d.ID)
}
