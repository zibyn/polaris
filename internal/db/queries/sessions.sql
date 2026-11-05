-- name: CreateSession :one
-- A NULL id_hash makes an App Session. The idle timeout and lifespan cap
-- are the Application's, or the defaults given for the Session's kind
-- (oidcstore.SessionDefaults). No row for a disabled User.
INSERT INTO sessions (id_hash, client_id, user_id, auth_time, amr, login_method, ip, user_agent, idle_timeout, max_lifetime)
SELECT sqlc.narg(id_hash), @client_id::text, u.id, @auth_time, @amr, @login_method::text, sqlc.narg(ip), sqlc.narg(user_agent),
       COALESCE((SELECT session_idle_timeout FROM applications WHERE applications.client_id = @client_id),
                make_interval(secs => @default_idle_secs::int)),
       COALESCE((SELECT session_max_lifetime FROM applications WHERE applications.client_id = @client_id),
                make_interval(secs => @default_max_secs::int))
FROM users u WHERE u.id = @user_id AND u.disabled_at IS NULL
RETURNING id, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: TouchSession :one
UPDATE sessions SET last_seen_at = now(), ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
WHERE sessions.id_hash = @id_hash AND sessions.id IN (SELECT l.id FROM live_sessions l)
RETURNING id, user_id, auth_time, amr, COALESCE(login_method, '')::text AS login_method, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: RenewSession :one
-- The same User signed in again: new cookie, new auth_time, same Session.
UPDATE sessions SET id_hash = @new_hash, auth_time = @auth_time, amr = @amr, login_method = @login_method::text, last_seen_at = now(),
    ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
WHERE sessions.id_hash = @old_hash AND sessions.user_id = @user_id
  AND sessions.id IN (SELECT l.id FROM live_sessions l)
RETURNING id, EXTRACT(EPOCH FROM idle_timeout)::integer AS idle_secs;

-- name: EndBrowserSession :exec
-- Queues a logout token for each Application a live Session issued tokens
-- to (ADR 0022); a lapsed one was ended by nobody and sends nothing.
WITH ended AS (
    UPDATE sessions SET ended_at = now() WHERE id_hash = $1 AND ended_at IS NULL
    RETURNING sessions.id, sessions.user_id, session_lapses_at(sessions) > now() AS live
)
INSERT INTO webhook_deliveries (client_id, kind, payload)
SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
FROM ended e JOIN session_applications sa ON sa.session_id = e.id JOIN applications a ON a.client_id = sa.client_id
WHERE e.live AND a.backchannel_logout_uri IS NOT NULL;

-- name: EndUserSession :execrows
-- An admin signs a User out of one Session, queuing its logout tokens;
-- audited with who did it.
WITH ended AS (
    UPDATE sessions SET ended_at = now()
    WHERE sessions.id = @id AND sessions.user_id = @user_id AND sessions.id IN (SELECT l.id FROM live_sessions l)
    RETURNING sessions.id, sessions.user_id, session_lapses_at(sessions) > now() AS live
), logout AS (
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
    FROM ended e JOIN session_applications sa ON sa.session_id = e.id JOIN applications a ON a.client_id = sa.client_id
    WHERE e.live AND a.backchannel_logout_uri IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'session.ended', ended.user_id, jsonb_build_object('session', ended.id, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM ended;

-- name: UserSessions :many
SELECT s.id, (s.id_hash IS NULL)::boolean AS app, s.client_id, COALESCE(a.name, s.client_id, '')::text AS application_name,
       s.auth_time, s.amr, s.last_seen_at, s.ip, s.user_agent,
       session_lapses_at(s)::timestamptz AS expires_at, s.ended_at,
       EXISTS (SELECT 1 FROM live_sessions l WHERE l.id = s.id)::boolean AS active
FROM sessions s LEFT JOIN applications a USING (client_id) WHERE s.user_id = $1
ORDER BY s.last_seen_at DESC;

-- name: DeleteOldSessions :exec
-- Ended or lapsed for more than 30 days (docs/spec/security-compliance.md).
DELETE FROM sessions
WHERE ended_at < now() - interval '30 days' OR session_lapses_at(sessions) < now() - interval '30 days';
