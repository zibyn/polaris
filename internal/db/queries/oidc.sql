-- name: Application :one
SELECT * FROM applications WHERE client_id = $1;

-- name: CreateApplication :exec
INSERT INTO applications (client_id, name, type, secret_hash, redirect_uris, post_logout_redirect_uris, default_api, backchannel_logout_uri)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: SaveGrant :exec
-- Revoking the refresh token of an App Session ends the Session: the chain
-- is the Session, and a logout token goes to each Application it issued
-- tokens to — this one too, though issued has not landed yet in this
-- statement's snapshot. The Session remembers the Application, for
-- Back-Channel Logout.
WITH g AS (
    INSERT INTO oidc_grants (id, auth_code_hash, refresh_token_hash, expires_at, session_id, sealed)
    VALUES (@id, @auth_code_hash, @refresh_token_hash, @expires_at, @session_id, @sealed)
    ON CONFLICT (id) DO UPDATE SET
        auth_code_hash = EXCLUDED.auth_code_hash,
        refresh_token_hash = EXCLUDED.refresh_token_hash,
        expires_at = EXCLUDED.expires_at,
        sealed = EXCLUDED.sealed
    RETURNING session_id
), issued AS (
    INSERT INTO session_applications (session_id, client_id)
    SELECT g.session_id, @client_id FROM g WHERE g.session_id IS NOT NULL
    ON CONFLICT DO NOTHING
), ended AS (
    UPDATE sessions SET ended_at = now()
    WHERE @revoked::boolean AND sessions.id_hash IS NULL AND sessions.ended_at IS NULL
      AND sessions.id = (SELECT g.session_id FROM g)
    RETURNING sessions.id, sessions.user_id, sessions.lapses_at > now() AS live
)
INSERT INTO webhook_deliveries (client_id, kind, payload)
SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
FROM ended e JOIN applications a
  ON a.client_id = @client_id OR a.client_id IN (SELECT sa.client_id FROM session_applications sa WHERE sa.session_id = e.id)
WHERE e.live AND a.backchannel_logout_uri IS NOT NULL;

-- name: RotateRefreshToken :execrows
-- Swaps the refresh token only if old_hash is still the current one, keeps
-- the old one as spent, and counts the refresh as Session activity, from
-- the refreshing device. No row: another request rotated it first.
WITH g AS (
    UPDATE oidc_grants SET refresh_token_hash = @new_hash, expires_at = @expires_at, sealed = @sealed
    WHERE oidc_grants.id = @id AND oidc_grants.refresh_token_hash = @old_hash
    RETURNING oidc_grants.id, oidc_grants.session_id
), touched AS (
    UPDATE sessions SET last_seen_at = now(), lapses_at = LEAST(now() + idle_timeout, auth_time + max_lifetime),
        ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
    WHERE sessions.id = (SELECT g.session_id FROM g)
)
INSERT INTO oidc_spent_refresh_tokens (hash, grant_id) SELECT @old_hash, g.id FROM g;

-- name: EndReusedRefreshToken :exec
-- A spent refresh token came back: end its grant's Session (a grant outside
-- any Session is deleted instead), queuing its logout tokens, and audit it.
WITH spent AS (
    SELECT g.id, g.session_id FROM oidc_spent_refresh_tokens s JOIN oidc_grants g ON g.id = s.grant_id
    WHERE s.hash = $1
), ended AS (
    UPDATE sessions SET ended_at = now()
    WHERE sessions.id IN (SELECT spent.session_id FROM spent) AND sessions.ended_at IS NULL
    RETURNING sessions.id, sessions.user_id, sessions.lapses_at > now() AS live
), logout AS (
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
    FROM ended e JOIN session_applications sa ON sa.session_id = e.id JOIN applications a ON a.client_id = sa.client_id
    WHERE e.live AND a.backchannel_logout_uri IS NOT NULL
), dropped AS (
    DELETE FROM oidc_grants WHERE oidc_grants.id IN (SELECT spent.id FROM spent WHERE spent.session_id IS NULL)
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'refresh_token.reused', ended.user_id, jsonb_build_object('session', ended.id) FROM ended;

-- name: GraceRefreshToken :one
-- The grant of a spent refresh token still in its grace window: the token
-- spent last on that grant, no more than grace_secs ago (ADR 0019).
SELECT s.grant_id FROM oidc_spent_refresh_tokens s
WHERE s.hash = @hash AND s.spent_at > now() - make_interval(secs => @grace_secs::int)
  AND s.spent_at = (SELECT max(t.spent_at) FROM oidc_spent_refresh_tokens t WHERE t.grant_id = s.grant_id);

-- name: GraceRotateRefreshToken :execrows
-- Rotates a grant whose old_hash is in its grace window from whatever token
-- is current now, like RotateRefreshToken (from the refreshing device too),
-- and audits the grace. No row: the token is out of grace.
WITH spent AS (
    SELECT s.grant_id FROM oidc_spent_refresh_tokens s
    WHERE s.hash = @old_hash AND s.spent_at > now() - make_interval(secs => @grace_secs::int)
      AND s.spent_at = (SELECT max(t.spent_at) FROM oidc_spent_refresh_tokens t WHERE t.grant_id = s.grant_id)
), cur AS (
    -- FOR UPDATE, held only within this statement (ADR 0030): a concurrent
    -- rotation makes it read the token current after that one, the old_hash
    -- spent below; a plain read would spend a hash already spent.
    SELECT g.id, g.refresh_token_hash FROM oidc_grants g WHERE g.id = (SELECT spent.grant_id FROM spent) FOR UPDATE
), g AS (
    UPDATE oidc_grants SET refresh_token_hash = @new_hash, expires_at = @expires_at, sealed = @sealed
    FROM cur WHERE oidc_grants.id = cur.id
    RETURNING oidc_grants.id, oidc_grants.session_id, cur.refresh_token_hash AS old_hash
), touched AS (
    UPDATE sessions SET last_seen_at = now(), lapses_at = LEAST(now() + idle_timeout, auth_time + max_lifetime),
        ip = sqlc.narg(ip), user_agent = sqlc.narg(user_agent)
    WHERE sessions.id = (SELECT g.session_id FROM g)
    RETURNING sessions.id, sessions.user_id
), audited AS (
    INSERT INTO audit_log (event, sub, detail)
    SELECT 'refresh_token.grace', touched.user_id, jsonb_build_object('session', touched.id) FROM touched
)
INSERT INTO oidc_spent_refresh_tokens (hash, grant_id) SELECT g.old_hash, g.id FROM g;

-- name: Grant :one
-- The Session check is a correlated EXISTS: OR with IN (SELECT ...) plans as
-- a hashed SubPlan that reads every live Session.
SELECT * FROM oidc_grants
WHERE oidc_grants.id = $1 AND (expires_at IS NULL OR expires_at > now())
  AND (session_id IS NULL OR EXISTS (SELECT 1 FROM sessions s
                                    WHERE s.id = oidc_grants.session_id AND s.ended_at IS NULL AND s.lapses_at > now()));

-- name: GrantByAuthCodeHash :one
SELECT * FROM oidc_grants
WHERE auth_code_hash = $1 AND (expires_at IS NULL OR expires_at > now())
  AND (session_id IS NULL OR EXISTS (SELECT 1 FROM sessions s
                                    WHERE s.id = oidc_grants.session_id AND s.ended_at IS NULL AND s.lapses_at > now()));

-- name: GrantByRefreshTokenHash :one
SELECT * FROM oidc_grants
WHERE refresh_token_hash = $1 AND (expires_at IS NULL OR expires_at > now())
  AND (session_id IS NULL OR EXISTS (SELECT 1 FROM sessions s
                                    WHERE s.id = oidc_grants.session_id AND s.ended_at IS NULL AND s.lapses_at > now()));

-- name: SaveAuthnSession :exec
INSERT INTO oidc_authn_sessions (id, expires_at, data) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at, data = EXCLUDED.data;

-- name: AuthnSession :one
SELECT data FROM oidc_authn_sessions WHERE id = $1 AND expires_at > now();

-- name: SaveChallengeSession :exec
INSERT INTO oidc_challenge_sessions (hash, client_id, expires_at, data)
VALUES (@hash, @client_id, now() + make_interval(secs => @ttl_secs::int), @data)
ON CONFLICT (hash) DO UPDATE SET expires_at = EXCLUDED.expires_at, data = EXCLUDED.data;

-- name: ChallengeSession :one
SELECT client_id, data FROM oidc_challenge_sessions WHERE hash = $1 AND expires_at > now();

-- name: DeleteChallengeSession :exec
DELETE FROM oidc_challenge_sessions WHERE hash = $1;

-- name: SaveLogoutSession :exec
INSERT INTO oidc_logout_sessions (id, expires_at, data) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at, data = EXCLUDED.data;

-- name: LogoutSession :one
SELECT data FROM oidc_logout_sessions WHERE id = $1 AND expires_at > now();

-- name: DeleteExpiredOIDC :exec
WITH g AS (DELETE FROM oidc_grants WHERE oidc_grants.expires_at < now()),
     a AS (DELETE FROM oidc_authn_sessions WHERE oidc_authn_sessions.expires_at < now()),
     c AS (DELETE FROM oidc_challenge_sessions WHERE oidc_challenge_sessions.expires_at < now()),
     p AS (DELETE FROM provider_logins WHERE provider_logins.expires_at < now()),
     j AS (DELETE FROM oidc_jtis WHERE oidc_jtis.expires_at < now())
DELETE FROM oidc_logout_sessions WHERE oidc_logout_sessions.expires_at < now();

-- name: InsertSigningKey :exec
-- generation is the newest key's read plus one: a replica that rotated
-- meanwhile took it already, and the unique key refuses the second.
INSERT INTO signing_keys (kid, sealed, generation) VALUES ($1, $2, $3);

-- name: SigningKeys :many
-- The published keys: the current one, plus each older key whose successor
-- came less than @retention ago. A newer key past that age means the next
-- key after this one is too.
SELECT kid, created_at, sealed, generation FROM signing_keys k
WHERE NOT EXISTS (
    SELECT 1 FROM signing_keys n
    WHERE n.created_at > k.created_at AND n.created_at <= now() - @retention::interval
)
ORDER BY created_at DESC, kid;

-- name: DeleteRetiredSigningKeys :exec
DELETE FROM signing_keys k WHERE EXISTS (
    SELECT 1 FROM signing_keys n
    WHERE n.created_at > k.created_at AND n.created_at <= now() - @retention::interval
);

-- name: SetRedirectURIs :exec
UPDATE applications SET redirect_uris = $2, post_logout_redirect_uris = $3 WHERE client_id = $1;

-- name: TokenRoles :one
-- A User's Roles on an API and the Permissions they add up to, for the
-- access token (RFC 9068 §2.2.3.1).
SELECT COALESCE(array_agg(DISTINCT ur.role ORDER BY ur.role), '{}')::text[] AS roles,
       COALESCE(array_agg(DISTINCT rp.permission ORDER BY rp.permission)
                FILTER (WHERE rp.permission IS NOT NULL), '{}')::text[] AS entitlements
FROM user_roles ur LEFT JOIN role_permissions rp USING (api, role)
WHERE ur.user_id = $1 AND ur.api = $2;

-- name: ApplicationTokenRoles :one
-- An M2M Application's Roles on its API and the Permissions they add up to,
-- for its client_credentials access token (ADR 0015).
SELECT COALESCE(array_agg(DISTINCT ar.role ORDER BY ar.role), '{}')::text[] AS roles,
       COALESCE(array_agg(DISTINCT rp.permission ORDER BY rp.permission)
                FILTER (WHERE rp.permission IS NOT NULL), '{}')::text[] AS entitlements
FROM application_roles ar LEFT JOIN role_permissions rp USING (api, role)
WHERE ar.client_id = $1 AND ar.api = $2;

-- name: ConsumeJTI :execrows
INSERT INTO oidc_jtis (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: LoginMethods :one
-- What the Application may be signed in with (ADR 0027): the login methods
-- the instance has on, narrowed to the Application's own set unless it
-- follows the instance. In the terms of applications.login_methods.
WITH instance AS (
    SELECT CASE kind WHEN 'phone' THEN 'sms' ELSE kind END AS method FROM channels
    UNION ALL SELECT 'password' FROM settings WHERE password_login <> 'off'
    UNION ALL SELECT 'passkey' FROM settings WHERE passkey_login
    UNION ALL SELECT 'provider:' || id FROM providers WHERE enabled
)
SELECT ARRAY(SELECT i.method FROM instance i WHERE a.login_methods IS NULL OR i.method = ANY (a.login_methods))::text[] AS open,
       (a.login_methods IS NOT NULL)::boolean AS own
FROM applications a WHERE a.client_id = $1;

-- name: Brand :one
-- The 品牌 the hosted pages of the Application client_id show: its own
-- items, the instance's where it has none. An unknown or empty client_id
-- gets the instance's.
SELECT COALESCE(a.brand_name, s.brand_name)::text AS name,
       COALESCE(a.brand_logo, s.brand_logo)::text AS logo,
       COALESCE(a.brand_color, s.brand_color)::text AS color
FROM settings s LEFT JOIN applications a ON a.client_id = @client_id;
