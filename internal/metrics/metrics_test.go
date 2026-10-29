package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/metrics"
)

func scrape(t *testing.T, h http.Handler) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(b)
}

func TestMetricsReadFromPostgres(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE settings SET daily_send_limit = 42`,
		`INSERT INTO sends (identifier, ip, sent_at) VALUES ('a@example.com', '10.0.0.1', now()), ('b@example.com', '10.0.0.1', now() - interval '25 hours')`,
		`INSERT INTO audit_log (event, at) VALUES
			('login.succeeded', now()), ('login.succeeded', now()), ('login.succeeded', now() - interval '25 hours'),
			('login.failed', now()),
			('login.ip_locked', now()), ('login.ip_locked', now()),
			('login.password_locked', now()), ('login.password_locked', now() - interval '2 days'),
			('webhook.failed', now())`,
		`INSERT INTO applications (client_id, name, type) VALUES ('app', 'App', 'public')`,
		`INSERT INTO webhook_deliveries (client_id, payload, attempts) VALUES ('app', '{}', 0), ('app', '{}', 1)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	h := metrics.Handler(pool)
	code, body := scrape(t, h)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	for _, want := range []string{
		"polaris_code_sends_last_24h 1\n",
		"polaris_daily_send_limit 42\n",
		"polaris_logins_succeeded_last_24h 2\n",
		"polaris_logins_failed_last_24h 1\n",
		`polaris_lockouts_last_24h{kind="ip"} 2` + "\n",
		`polaris_lockouts_last_24h{kind="password"} 1` + "\n",
		"polaris_webhook_deliveries_pending 2\n",
		"polaris_webhook_deliveries_retrying 1\n",
		"polaris_webhook_dropped_last_24h 1\n",
		"# TYPE polaris_code_send_failures_total counter",
		"# TYPE polaris_tokens_issued_total counter",
		"go_goroutines ",
		"process_",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}

	// Read on every scrape, not cached.
	if _, err := pool.Exec(ctx, `UPDATE settings SET daily_send_limit = 0`); err != nil {
		t.Fatal(err)
	}
	if _, body := scrape(t, h); !strings.Contains(body, "polaris_daily_send_limit 0\n") {
		t.Errorf("limit not re-read:\n%s", body)
	}

	// A failed read is a failed scrape, not zeros.
	pool.Close()
	if code, body := scrape(t, h); code/100 == 2 {
		t.Errorf("database down: %d %s", code, body)
	}
}
