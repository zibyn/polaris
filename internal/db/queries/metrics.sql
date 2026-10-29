-- name: Metrics :one
-- Everything /metrics reads from PG, in one round trip (ADR 0024). Counts
-- over the last 24 hours; audit counts use the audit_log (event, at) index.
SELECT (SELECT count(*) FROM sends WHERE sent_at >= now() - interval '1 day') AS code_sends,
       (SELECT daily_send_limit FROM settings) AS daily_send_limit,
       (SELECT count(*) FROM audit_log WHERE event = 'login.succeeded' AND at >= now() - interval '1 day') AS logins_succeeded,
       (SELECT count(*) FROM audit_log WHERE event = 'login.failed' AND at >= now() - interval '1 day') AS logins_failed,
       (SELECT count(*) FROM audit_log WHERE event = 'login.ip_locked' AND at >= now() - interval '1 day') AS ip_lockouts,
       (SELECT count(*) FROM audit_log WHERE event = 'login.password_locked' AND at >= now() - interval '1 day') AS password_lockouts,
       (SELECT count(*) FROM webhook_deliveries) AS webhook_pending,
       (SELECT count(*) FROM webhook_deliveries WHERE attempts > 0) AS webhook_retrying,
       (SELECT count(*) FROM audit_log WHERE event = 'webhook.failed' AND at >= now() - interval '1 day') AS webhook_dropped;
