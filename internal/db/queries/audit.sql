-- name: Audit :exec
INSERT INTO audit_log (event, sub, detail) VALUES ($1, $2, $3);

-- name: AuditedSince :one
SELECT EXISTS (SELECT 1 FROM audit_log WHERE event = $1 AND at > $2);

-- name: DeleteOldAudit :exec
DELETE FROM audit_log WHERE at < now() - make_interval(days => (SELECT audit_retention_days FROM settings));

-- name: UserLogins :many
-- The account center's 最近登录: the last 30 days, newest first, at most 50.
-- A deleted Application falls back to the client_id.
SELECT l.at, l.event, l.detail, COALESCE(a.name, l.detail->>'client_id', '')::text AS application
FROM audit_log l LEFT JOIN applications a ON a.client_id = l.detail->>'client_id'
WHERE l.sub = @sub::text AND l.event IN ('login.succeeded', 'login.failed', 'login.password_locked')
  AND l.at > now() - interval '30 days'
ORDER BY l.at DESC, l.id DESC
LIMIT 50;

-- name: UserLoginFailures :one
SELECT count(*) FROM audit_log WHERE sub = @sub::text AND event = 'login.failed' AND at > now() - interval '30 days';
