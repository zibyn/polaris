-- name: AccountSession :one
-- The live Session an account center request comes from.
SELECT s.auth_time FROM sessions s
WHERE s.id = @id AND s.user_id = @user_id AND s.id IN (SELECT l.id FROM live_sessions l);

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
       s.passkey_login
FROM users u, settings s
WHERE u.id = $1;

-- name: MustKeepTwoFactor :one
-- 管理员必须启用两步验证或 Passkey is on, the User holds a Management API
-- Role, and no Passkey counts (the switch is off, or they have none):
-- turning 两步验证 off would lock them out of the Management API.
SELECT (s.admins_need_two_factor AND NOT (s.passkey_login AND has_passkey($1)) AND EXISTS (
    SELECT 1 FROM user_roles r WHERE r.user_id = $1 AND r.api = 'urn:stars-auth:management-api'))::boolean AS must
FROM settings s;

-- name: MustKeepPasskey :one
-- The switch is on, the User holds a Management API Role, has no confirmed
-- TOTP, and id is their last Passkey: deleting it would lock them out. The
-- id must be theirs, so an unknown id is 404, not 409.
SELECT (s.passkey_login AND s.admins_need_two_factor AND NOT totp_confirmed(@sub) AND EXISTS (
    SELECT 1 FROM user_roles r WHERE r.user_id = @sub AND r.api = 'urn:stars-auth:management-api')
    AND EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = @sub AND p.id = @id)
    AND NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = @sub AND p.id <> @id))::boolean AS must
FROM settings s;

-- name: Reauthenticate :exec
-- The User proved themselves again in this Session.
UPDATE sessions SET auth_time = now(), amr = @amr WHERE id = @id AND user_id = @user_id;

-- name: LockUser :one
-- Serialises changes to a User's login paths.
SELECT id FROM users WHERE id = $1 FOR UPDATE;

-- name: LoginPaths :one
-- What a User could sign in with (docs/spec/identity.md#不变式).
SELECT COALESCE(array_agg(kind ORDER BY kind) FILTER (WHERE kind IS NOT NULL), '{}')::text[] AS identifiers,
       EXISTS (SELECT 1 FROM passwords p WHERE p.user_id = $1) AS has_password,
       EXISTS (SELECT 1 FROM external_identities e JOIN providers pr ON pr.id = e.provider
               WHERE e.user_id = $1 AND pr.enabled) AS has_external_identity
FROM identifiers WHERE user_id = $1;

-- name: RemoveIdentifier :execrows
-- Audited as done by the User.
WITH gone AS (
    DELETE FROM identifiers WHERE user_id = @user_id AND kind = @kind RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'identifier.removed', gone.user_id, jsonb_build_object('kind', @kind::text, 'by', gone.user_id) FROM gone;

-- name: PutPassword :exec
-- Audited as done by the User.
WITH put AS (
    INSERT INTO passwords (user_id, hash) VALUES (@user_id, @hash)
    ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash
)
INSERT INTO audit_log (event, sub, detail)
VALUES ('password.changed', @user_id::text, jsonb_build_object('by', @user_id::text));

-- name: RemovePassword :execrows
-- Audited as done by the User.
WITH gone AS (
    DELETE FROM passwords WHERE user_id = @user_id RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'password.removed', gone.user_id, jsonb_build_object('by', gone.user_id) FROM gone;

-- name: UserConsents :many
SELECT version, client_id, at FROM consents WHERE user_id = $1 ORDER BY at;

-- name: UserAudit :many
-- The audit events about a User, oldest first.
SELECT at, event, detail FROM audit_log WHERE sub = $1 ORDER BY id;
