// Package metrics serves Prometheus /metrics (ADR 0024). What PG already
// records is read from it at scrape time as gauges; only what PG does not
// record is counted in process.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

var (
	// CodeSendFailures counts a Channel's Send or SendLink returning an
	// error, by channel kind (sms, email). Refusals by the send limits are
	// not failures.
	CodeSendFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "polaris_code_send_failures_total",
		Help: "Channel deliveries (codes and invitations) that returned an error.",
	}, []string{"kind"})
	// TokensIssued counts access tokens issued, by grant_type. No client_id:
	// label cardinality stays fixed.
	TokensIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "polaris_tokens_issued_total",
		Help: "Access tokens issued by the token endpoint.",
	}, []string{"grant_type"})
)

// Handler serves /metrics: Go runtime and process metrics, the in-process
// counters, and the gauges read from pool on each scrape. A failed read
// fails the scrape (HTTP 500) rather than reporting zeros.
func Handler(pool *pgxpool.Pool) http.Handler {
	// Exported at 0 from the start, so rate() and absent() see them.
	for _, k := range []string{"sms", "email"} {
		CodeSendFailures.WithLabelValues(k)
	}
	for _, g := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		TokensIssued.WithLabelValues(g)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		CodeSendFailures, TokensIssued,
		pgCollector{sqlc.New(pool)},
	)
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

func gauge(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

var (
	codeSends       = gauge("polaris_code_sends_last_24h", "Codes and invitations sent in the last 24 hours, as counted against the daily send limit.")
	dailySendLimit  = gauge("polaris_daily_send_limit", "The instance daily send limit; 0 means unlimited.")
	loginsSucceeded = gauge("polaris_logins_succeeded_last_24h", "login.succeeded audit events in the last 24 hours.")
	loginsFailed    = gauge("polaris_logins_failed_last_24h", "login.failed audit events in the last 24 hours.")
	lockouts        = gauge("polaris_lockouts_last_24h", "IP and password lockouts in the last 24 hours.", "kind")
	webhookPending  = gauge("polaris_webhook_deliveries_pending", "Webhook deliveries waiting to go out.")
	webhookRetrying = gauge("polaris_webhook_deliveries_retrying", "Pending webhook deliveries that have failed at least once.")
	webhookDropped  = gauge("polaris_webhook_dropped_last_24h", "Webhook deliveries given up on (webhook.failed) in the last 24 hours.")
	allGauges       = []*prometheus.Desc{codeSends, dailySendLimit, loginsSucceeded, loginsFailed, lockouts, webhookPending, webhookRetrying, webhookDropped}
)

type pgCollector struct{ q *sqlc.Queries }

func (pgCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range allGauges {
		ch <- d
	}
}

func (c pgCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := c.q.Metrics(ctx)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(codeSends, err)
		return
	}
	g := func(d *prometheus.Desc, v int64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(v), labels...)
	}
	g(codeSends, r.CodeSends)
	g(dailySendLimit, int64(r.DailySendLimit))
	g(loginsSucceeded, r.LoginsSucceeded)
	g(loginsFailed, r.LoginsFailed)
	g(lockouts, r.IpLockouts, "ip")
	g(lockouts, r.PasswordLockouts, "password")
	g(webhookPending, r.WebhookPending)
	g(webhookRetrying, r.WebhookRetrying)
	g(webhookDropped, r.WebhookDropped)
}
