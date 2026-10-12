-- name: LockSetup :one
SELECT setup_token, setup_done FROM settings FOR UPDATE;

-- name: SetSetupToken :exec
UPDATE settings SET setup_token = $1;

-- name: CloseSetup :exec
UPDATE settings SET setup_token = NULL, setup_done = true;

-- name: CreateUser :exec
-- The new User also picks up every default Role, in the same statement, so
-- every creation path (code or password sign-up, Provider, bootstrap) agrees
-- and the set is whatever the default Roles are at that moment.
WITH new_user AS (
    INSERT INTO users (id) VALUES ($1)
    RETURNING id
)
INSERT INTO user_roles (user_id, api, role)
SELECT u.id, r.api, r.key FROM new_user u JOIN roles r ON r.default_role;

-- name: AddIdentifier :exec
INSERT INTO identifiers (user_id, kind, value) VALUES ($1, $2, $3);

-- name: SetPassword :exec
INSERT INTO passwords (user_id, hash) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash;

-- name: AssignRole :exec
INSERT INTO user_roles (user_id, api, role) VALUES ($1, $2, $3);

-- name: PasswordByIdentifier :one
SELECT i.user_id, p.hash, (u.disabled_at IS NOT NULL)::boolean AS disabled
FROM identifiers i JOIN passwords p USING (user_id) JOIN users u ON u.id = i.user_id
WHERE i.value = $1;

-- name: PasswordLogin :one
SELECT password_login FROM settings;

-- name: UserByIdentifier :one
SELECT i.user_id, (u.disabled_at IS NOT NULL)::boolean AS disabled
FROM identifiers i JOIN users u ON u.id = i.user_id WHERE i.value = $1;

-- name: UserIdentifiers :many
SELECT kind, value FROM identifiers WHERE user_id = $1;

-- name: NeedsPhone :one
-- The instance requires a phone number and the User has none.
SELECT (s.require_phone AND NOT EXISTS (SELECT 1 FROM identifiers i WHERE i.user_id = $1 AND i.kind = 'phone'))::boolean
FROM settings s;

-- name: Terms :one
SELECT terms_url, privacy_url, terms_version FROM settings;

-- name: NeedsConsent :one
-- The instance has terms and the User has not agreed to this version.
SELECT (s.terms_version <> '' AND NOT EXISTS (
    SELECT 1 FROM consents c WHERE c.user_id = $1 AND c.version = s.terms_version))::boolean
FROM settings s;

-- name: RecordConsent :exec
INSERT INTO consents (user_id, version, client_id) VALUES ($1, $2, $3);
