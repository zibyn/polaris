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

-- name: ReplaceIdentifier :execrows
-- Sets a User's Identifier of a kind, replacing the one they had. Audited
-- with who did it, without the values.
WITH put AS (
    INSERT INTO identifiers (user_id, kind, value)
    SELECT users.id, @kind, @value FROM users WHERE users.id = @user_id
    ON CONFLICT (user_id, kind) DO UPDATE SET value = EXCLUDED.value
    RETURNING identifiers.user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'identifier.replaced', put.user_id, jsonb_build_object('kind', @kind::text, 'by', @by::text) FROM put;

-- name: SetPassword :exec
INSERT INTO passwords (user_id, hash) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash;

-- name: AssignRole :exec
INSERT INTO user_roles (user_id, api, role) VALUES ($1, $2, $3);

-- name: LockOwners :exec
-- Serialises changes that could leave the instance without an owner.
SELECT pg_advisory_xact_lock(hashtext('owners'));

-- name: CountOwners :one
-- Only an active owner counts: a 待激活 owner can sign in but gets no token,
-- so they cannot administer the instance.
SELECT count(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id
WHERE ur.api = 'urn:polaris:management-api' AND ur.role = 'owner'
  AND u.disabled_at IS NULL AND u.status = 'active';

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

-- name: SetUserPending :exec
-- 管理员创建的 User 进入待激活 (ADR 0016). 单独一条语句, 不并进 CreateUser:
-- 默认 Role 的定义只有那一处, 每条创建途径才都一致.
UPDATE users SET status = 'pending' WHERE id = $1;

-- name: UserPending :one
-- 待激活 comes from users.pending, which defines it once (迁移 00027):
-- pending 且未禁用; 禁用永远优先 (一个禁用的 User 根本登录不了).
SELECT pending FROM users WHERE id = $1;

-- name: ActivateUser :execrows
-- 强制改密 (ADR 0016): 待激活的 User 写进自己的密码, 随即激活.
-- 单独一条通路, 不复用账号中心的 PutPassword — 那条要求近期重新认证, 而
-- 重新认证对开了两步验证的 User 一律拒绝密码和验证码, 2FA 用户会卡死.
-- put 挂在 activated 上, 只有这一行真的还是 pending 才写得进去: 重放一个
-- 已激活账号的 auth_session 改不动密码, 也不会多记一条审计.
WITH activated AS (
    UPDATE users SET status = 'active' WHERE users.id = @user_id AND users.status = 'pending' RETURNING users.id
), put AS (
    INSERT INTO passwords (user_id, hash) SELECT activated.id, @hash FROM activated
    ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash
    RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'password.changed', put.user_id, jsonb_build_object('by', put.user_id) FROM put;

-- name: MaySignUp :one
-- Whether value may be signed in with by code (ADR 0021): a User holds it,
-- or the instance is open to new ones.
SELECT (s.open_registration OR EXISTS (SELECT 1 FROM identifiers i WHERE i.value = @value::text))::boolean
FROM settings s;

-- name: RegistrationOpen :one
SELECT open_registration FROM settings;
