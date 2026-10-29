-- name: CreateSession :one
-- A NULL id_hash makes an App Session. The idle timeout is the
-- Application's, or the default of the Session's kind. No row for a
-- disabled User.
INSERT INTO sessions (id_hash, client_id, user_id, auth_time, amr, ip, user_agent, idle_timeout)
SELECT sqlc.narg(id_hash), @client_id::text, u.id, @auth_time, @amr, sqlc.narg(ip), sqlc.narg(user_agent),
       COALESCE((SELECT session_idle_timeout FROM applications WHERE applications.client_id = @client_id),
                CASE WHEN sqlc.narg(id_hash)::bytea IS NULL THEN interval '90 days' ELSE interval '30 days' END)
FROM users u WHERE u.id = @user_id AND u.disabled_at IS NULL
RETURNING id, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: TouchSession :one
UPDATE sessions SET last_seen_at = now(), ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
WHERE sessions.id_hash = @id_hash AND sessions.id IN (SELECT l.id FROM live_sessions l)
RETURNING id, user_id, auth_time, amr, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: RenewSession :one
-- The same User signed in again: new cookie, new auth_time, same Session.
UPDATE sessions SET id_hash = @new_hash, auth_time = @auth_time, amr = @amr, last_seen_at = now(),
    ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
WHERE sessions.id_hash = @old_hash AND sessions.user_id = @user_id
  AND sessions.id IN (SELECT l.id FROM live_sessions l)
RETURNING id, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: EndBrowserSession :exec
UPDATE sessions SET ended_at = now() WHERE id_hash = $1 AND ended_at IS NULL;

-- name: EndUserSession :execrows
-- An admin signs a User out of one Session; audited with who did it.
WITH ended AS (
    UPDATE sessions SET ended_at = now()
    WHERE sessions.id = @id AND sessions.user_id = @user_id AND sessions.id IN (SELECT l.id FROM live_sessions l)
    RETURNING sessions.id, sessions.user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'session.ended', ended.user_id, jsonb_build_object('session', ended.id, 'by', @by::text) FROM ended;

-- name: UserSessions :many
SELECT s.id, (s.id_hash IS NULL)::boolean AS app, s.client_id, COALESCE(a.name, s.client_id, '')::text AS application_name,
       s.auth_time, s.amr, s.last_seen_at, s.ip, s.user_agent,
       (s.last_seen_at + s.idle_timeout)::timestamptz AS expires_at, s.ended_at,
       (s.id IN (SELECT l.id FROM live_sessions l))::boolean AS active
FROM sessions s LEFT JOIN applications a USING (client_id) WHERE s.user_id = $1
ORDER BY s.last_seen_at DESC;

-- name: DeleteOldSessions :exec
-- Ended or idle for more than 30 days (docs/spec/security-compliance.md).
DELETE FROM sessions
WHERE ended_at < now() - interval '30 days'
   OR last_seen_at + idle_timeout < now() - interval '30 days';
