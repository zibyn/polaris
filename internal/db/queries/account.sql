-- name: AccountSession :one
-- The live Session an account center request comes from, and whether the
-- User is 待激活: no token is ever issued to such a User (ADR 0016), so the
-- flag is normally false — read here rather than in a second query so every
-- request pays nothing extra for the check.
SELECT s.auth_time, u.pending
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.id = @id AND s.user_id = @user_id AND s.ended_at IS NULL AND s.lapses_at > now();

-- name: AccountUser :one
SELECT u.created_at,
       COALESCE((SELECT json_agg(json_build_object('kind', i.kind, 'value', i.value) ORDER BY i.kind)
                 FROM identifiers i WHERE i.user_id = u.id), '[]')::jsonb AS identifiers,
       EXISTS (SELECT 1 FROM passwords p WHERE p.user_id = u.id) AS has_password,
       -- The password login setting lets this User use a password.
       (s.password_login = 'on')::boolean AS password_allowed,
       -- When 两步验证 was turned on; null while it is off.
       (SELECT t.confirmed_at FROM totp_credentials t WHERE t.user_id = u.id) AS two_factor_since,
       (SELECT count(*) FROM recovery_codes c WHERE c.user_id = u.id AND c.used_at IS NULL) AS recovery_codes_left,
       -- Whether the instance offers Passkey login: the account center hides
       -- its Passkey section and reauthentication way while it does not.
       s.passkey_login,
       -- Holds a Management API Role: the account center links to the console.
       EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = u.id AND r.api = 'urn:polaris:management-api') AS admin
FROM users u, settings s
WHERE u.id = $1;

-- name: SecondFactors :one
-- What 管理员必须启用两步验证或 Passkey weighs for sub turning off 两步验证
-- or deleting the Passkey passkey_id (account.mustKeep): the settings, whether
-- sub holds a Management API Role, and their second factors.
SELECT s.admins_need_two_factor, s.passkey_login,
       EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = @sub AND r.api = 'urn:polaris:management-api') AS admin,
       EXISTS (SELECT 1 FROM totp_credentials t WHERE t.user_id = @sub AND t.confirmed_at IS NOT NULL) AS totp,
       (SELECT count(*) FROM passkeys p WHERE p.user_id = @sub) AS passkeys,
       EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = @sub AND p.id = @passkey_id::text) AS owns_passkey
FROM settings s;

-- name: Reauthenticate :exec
-- The User proved themselves again in this Session; the lifespan cap
-- counts from now (see CreateSession for lapses_at).
UPDATE sessions SET auth_time = now(), amr = @amr, lapses_at = LEAST(last_seen_at + idle_timeout, now() + max_lifetime)
WHERE id = @id AND user_id = @user_id;

-- name: LoginPaths :one
-- What a User could sign in with (docs/spec/identity.md#不变式).
SELECT COALESCE(array_agg(kind ORDER BY kind) FILTER (WHERE kind IS NOT NULL), '{}')::text[] AS identifiers,
       -- A password is no way in while password login is off.
       EXISTS (SELECT 1 FROM passwords p, settings s
               WHERE p.user_id = $1 AND s.password_login = 'on') AS password_counts,
       EXISTS (SELECT 1 FROM external_identities e JOIN providers pr ON pr.id = e.provider
               WHERE e.user_id = $1 AND pr.enabled) AS has_external_identity
FROM identifiers WHERE user_id = $1;

-- name: RemoveIdentifier :execrows
-- Audited as done by the User; queues user.updated.
WITH gone AS (
    DELETE FROM identifiers WHERE user_id = @user_id AND kind = @kind RETURNING user_id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', gone.user_id, 'changed', ARRAY[@kind::text])
    FROM gone JOIN applications a ON a.webhook_url IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'identifier.removed', gone.user_id, jsonb_build_object('kind', @kind::text, 'by', gone.user_id, 'byType', 'user') FROM gone;

-- name: PutPassword :exec
-- Audited as done by the User.
WITH put AS (
    INSERT INTO passwords (user_id, hash) VALUES (@user_id, @hash)
    ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash
)
INSERT INTO audit_log (event, sub, detail)
VALUES ('password.changed', @user_id::text, jsonb_build_object('by', @user_id::text, 'byType', 'user'));

-- name: RemovePassword :execrows
-- Audited as done by the User.
WITH gone AS (
    DELETE FROM passwords WHERE user_id = @user_id RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'password.removed', gone.user_id, jsonb_build_object('by', gone.user_id, 'byType', 'user') FROM gone;

-- name: UserConsents :many
SELECT version, client_id, at FROM consents WHERE user_id = $1 ORDER BY at;

-- name: UserAudit :many
-- The audit events about a User, oldest first.
SELECT at, event, detail FROM audit_log WHERE sub = $1 ORDER BY id;
