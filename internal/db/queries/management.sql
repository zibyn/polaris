-- name: Caller :one
-- Holding any Role on the API makes an admin, even one with no Permissions;
-- a disabled User is none. Admins must satisfy 两步验证或 Passkey when the
-- settings say so (twofactor.Satisfied, from the facts here).
SELECT count(*) > 0 AS admin,
       COALESCE(array_agg(DISTINCT rp.permission ORDER BY rp.permission)
                FILTER (WHERE rp.permission IS NOT NULL), '{}')::text[] AS permissions,
       EXISTS (SELECT 1 FROM totp_credentials t WHERE t.user_id = @sub::text AND t.confirmed_at IS NOT NULL) AS totp,
       EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = @sub::text) AS has_passkey,
       (SELECT passkey_login FROM settings) AS passkey_login,
       (SELECT admins_need_two_factor FROM settings) AS two_factor_required
FROM user_roles ur LEFT JOIN role_permissions rp USING (api, role)
WHERE ur.user_id = @sub AND ur.api = @api
  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = ur.user_id AND u.disabled_at IS NOT NULL);

-- name: M2MCaller :one
-- An M2M Application calling an API as itself (ADR 0015): the Permissions of
-- the Roles it holds there, read live, so deleting the Application or taking
-- a Role away closes it out on the next request. is_m2m_application is false
-- when the sub names no m2m Application, and then the caller is no one we know.
SELECT EXISTS (SELECT 1 FROM applications a WHERE a.client_id = @client_id AND a.type = 'm2m') AS is_m2m_application,
       count(*) > 0 AS admin,
       COALESCE(array_agg(DISTINCT rp.permission ORDER BY rp.permission)
                FILTER (WHERE rp.permission IS NOT NULL), '{}')::text[] AS permissions
FROM application_roles ar LEFT JOIN role_permissions rp USING (api, role)
WHERE ar.client_id = @client_id AND ar.api = @api;

-- name: ListUsers :many
-- Search matches part of the sub or of any Identifier. An empty role skips
-- the Role filter, and 'any' the status one.
-- ponytail: strpos scans every row; add a pg_trgm index when the pool is big.
SELECT u.id, u.created_at, u.disabled_at, u.pending,
       COALESCE((SELECT json_agg(json_build_object('kind', i.kind, 'value', i.value) ORDER BY i.kind)
                 FROM identifiers i WHERE i.user_id = u.id), '[]')::jsonb AS identifiers,
       COALESCE((SELECT json_agg(json_build_object('api', r.api, 'key', r.key, 'name', r.name) ORDER BY r.api, r.key)
                 FROM user_roles ur JOIN roles r ON r.api = ur.api AND r.key = ur.role
                 WHERE ur.user_id = u.id), '[]')::jsonb AS roles
FROM users u
WHERE (@search::text = ''
       OR strpos(u.id, upper(@search)) > 0
       OR EXISTS (SELECT 1 FROM identifiers i WHERE i.user_id = u.id AND strpos(i.value, lower(@search)) > 0))
  AND (@role::text = ''
       OR EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.api = @api AND ur.role = @role))
  -- 待激活 by users.pending, the one definition; 剩下的一律算
  -- active, 被禁用的 User 也在那一侧 —— 他根本登录不了.
  AND (@status::text = 'any'
       OR (@status::text = 'pending') = u.pending)
ORDER BY u.created_at DESC, u.id
LIMIT @lim OFFSET @off;

-- name: GetUser :one
SELECT u.id, u.created_at, u.disabled_at, u.pending,
       COALESCE((SELECT json_agg(json_build_object('kind', i.kind, 'value', i.value) ORDER BY i.kind)
                 FROM identifiers i WHERE i.user_id = u.id), '[]')::jsonb AS identifiers,
       COALESCE((SELECT json_agg(json_build_object('api', r.api, 'key', r.key, 'name', r.name) ORDER BY r.api, r.key)
                 FROM user_roles ur JOIN roles r ON r.api = ur.api AND r.key = ur.role
                 WHERE ur.user_id = u.id), '[]')::jsonb AS roles,
       EXISTS (SELECT 1 FROM passwords p WHERE p.user_id = u.id) AS has_password,
       EXISTS (SELECT 1 FROM totp_credentials t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL) AS two_factor,
       EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id) AS has_passkey,
       (SELECT passkey_login FROM settings) AS passkey_login,
       -- 注册邀请现在是什么状态: 表里还挂着一条还没到期的就是「已发出」, 上
       -- 一条被本人用掉了就是「已接受」(users.invite_accepted_at), 其余
       -- 是「没发出过」——撤销过、过期了都算, 不等清理任务把那行扫掉。
       (SELECT i.expires_at FROM invites i
        WHERE i.user_id = u.id AND i.expires_at > now()) AS invite_expires_at,
       (u.invite_accepted_at IS NOT NULL)::boolean AS invite_accepted
FROM users u
WHERE u.id = $1;

-- name: ListRoles :many
SELECT r.api, a.name AS api_name, r.key, r.name, r.builtin
FROM roles r JOIN apis a ON a.identifier = r.api
ORDER BY a.builtin DESC, r.api, r.builtin DESC, r.key;

-- name: SetUserRoles :exec
-- Makes roles a User's Roles on an API; audited with who did it, and queues
-- user.updated when that changed anything.
WITH gone AS (
    DELETE FROM user_roles
    WHERE user_roles.user_id = @user_id AND user_roles.api = @api AND NOT (user_roles.role = ANY (@roles::text[]))
    RETURNING user_roles.user_id
), added AS (
    INSERT INTO user_roles (user_id, api, role)
    SELECT @user_id, @api, r FROM unnest(@roles::text[]) AS r
    ON CONFLICT DO NOTHING
    RETURNING user_roles.user_id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', @user_id::text, 'changed', '{roles}'::text[])
    FROM applications a
    WHERE a.webhook_url IS NOT NULL AND (EXISTS (SELECT 1 FROM gone) OR EXISTS (SELECT 1 FROM added))
)
INSERT INTO audit_log (event, sub, detail)
VALUES ('roles.assigned', @user_id::text, jsonb_build_object('api', @api::text, 'roles', @roles::text[], 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')));

-- name: ListAPIs :many
-- Every API with its Permissions and Roles; users and applications count who
-- holds a Role.
SELECT a.identifier, a.name, a.builtin,
       COALESCE((SELECT json_agg(json_build_object('key', p.key, 'name', p.name, 'builtin', p.builtin) ORDER BY p.key)
                 FROM permissions p WHERE p.api = a.identifier), '[]')::jsonb AS permissions,
       COALESCE((SELECT json_agg(json_build_object(
                     'key', r.key, 'name', r.name, 'builtin', r.builtin, 'default', r.default_role,
                     'permissions', COALESCE((SELECT json_agg(rp.permission ORDER BY rp.permission) FROM role_permissions rp
                                              WHERE rp.api = r.api AND rp.role = r.key), '[]'),
                     'users', (SELECT count(*) FROM user_roles ur WHERE ur.api = r.api AND ur.role = r.key),
                     'applications', (SELECT count(*) FROM application_roles ar WHERE ar.api = r.api AND ar.role = r.key))
                     ORDER BY r.builtin DESC, r.key)
                 FROM roles r WHERE r.api = a.identifier), '[]')::jsonb AS roles
FROM apis a
ORDER BY a.builtin DESC, a.identifier;

-- name: APIBuiltin :one
SELECT builtin FROM apis WHERE identifier = $1;

-- name: PutAPI :execrows
-- Audited with who did it; no row for a built-in API.
WITH put AS (
    INSERT INTO apis (identifier, name) VALUES (@identifier, @name)
    ON CONFLICT (identifier) DO UPDATE SET name = EXCLUDED.name WHERE NOT apis.builtin
    RETURNING apis.identifier
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'api.saved', NULL, jsonb_build_object('api', put.identifier, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM put;

-- name: DeleteAPI :execrows
-- Its Permissions, Roles and their assignments go with it, but only when
-- force confirms that; no row while someone holds one of its Roles. Each
-- User who held one gets user.updated. Audited with who did it.
WITH gone AS (
    DELETE FROM apis
    WHERE apis.identifier = @identifier AND NOT apis.builtin
      AND (@force::boolean OR NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.api = apis.identifier))
    RETURNING apis.identifier
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', h.user_id, 'changed', '{roles}'::text[])
    FROM (SELECT DISTINCT ur.user_id FROM user_roles ur JOIN gone ON ur.api = gone.identifier) h JOIN applications a ON a.webhook_url IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'api.deleted', NULL, jsonb_build_object('api', gone.identifier, 'force', @force::boolean, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: PutPermission :exec
-- Audited with who did it.
WITH put AS (
    INSERT INTO permissions (api, key, name) VALUES (@api, @key, @name)
    ON CONFLICT (api, key) DO UPDATE SET name = EXCLUDED.name
)
INSERT INTO audit_log (event, sub, detail)
VALUES ('permission.saved', NULL, jsonb_build_object('api', @api::text, 'key', @key::text, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')));

-- name: DeletePermission :execrows
-- Its Roles lose it too (role_permissions cascades). Audited with who did it.
WITH gone AS (
    DELETE FROM permissions WHERE permissions.api = @api AND permissions.key = @key AND NOT permissions.builtin
    RETURNING permissions.api, permissions.key
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'permission.deleted', NULL, jsonb_build_object('api', gone.api, 'key', gone.key, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: PutRole :execrows
-- default_role is only ever true for a business API Role; the Management API
-- rejects it before it gets here.
INSERT INTO roles (api, key, name, default_role) VALUES ($1, $2, $3, $4)
ON CONFLICT (api, key) DO UPDATE SET name = EXCLUDED.name, default_role = EXCLUDED.default_role WHERE NOT roles.builtin;

-- name: SetRolePermissions :exec
WITH gone AS (
    DELETE FROM role_permissions
    WHERE role_permissions.api = @api AND role_permissions.role = @role AND NOT (role_permissions.permission = ANY (@permissions::text[]))
)
INSERT INTO role_permissions (api, role, permission)
SELECT @api, @role, p FROM unnest(@permissions::text[]) AS p
ON CONFLICT DO NOTHING;

-- name: RoleUsers :one
-- How many Users and how many M2M Applications hold the Role; its built-in
-- flag guards changes.
SELECT r.builtin,
       (SELECT count(*) FROM user_roles ur WHERE ur.api = r.api AND ur.role = r.key) AS users,
       (SELECT count(*) FROM application_roles ar WHERE ar.api = r.api AND ar.role = r.key) AS applications
FROM roles r WHERE r.api = $1 AND r.key = $2;

-- name: DeleteRole :execrows
-- Its assignments go with it (user_roles and application_roles cascade), but
-- only when force confirms that; no row while anyone holds it. Each User
-- who held it gets user.updated. Audited with who did it.
WITH gone AS (
    DELETE FROM roles
    WHERE roles.api = @api AND roles.key = @key AND NOT roles.builtin
      AND (@force::boolean OR NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.api = roles.api AND ur.role = roles.key)
                                 AND NOT EXISTS (SELECT 1 FROM application_roles ar WHERE ar.api = roles.api AND ar.role = roles.key))
    RETURNING roles.api, roles.key
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', ur.user_id, 'changed', '{roles}'::text[])
    FROM user_roles ur JOIN gone ON ur.api = gone.api AND ur.role = gone.key JOIN applications a ON a.webhook_url IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'role.deleted', NULL, jsonb_build_object('api', gone.api, 'key', gone.key, 'force', @force::boolean, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: SetApplicationRoles :exec
-- Makes roles an M2M Application's Roles on its default API, audited with
-- who did it. Its client_id is the event's subject, in the detail.
WITH gone AS (
    DELETE FROM application_roles
    WHERE application_roles.client_id = @client_id AND application_roles.api = @api AND NOT (application_roles.role = ANY (@roles::text[]))
), added AS (
    INSERT INTO application_roles (client_id, api, role)
    SELECT @client_id, @api, r FROM unnest(@roles::text[]) AS r
    ON CONFLICT DO NOTHING
)
INSERT INTO audit_log (event, sub, detail)
VALUES ('application_roles.assigned', NULL,
        jsonb_build_object('clientId', @client_id::text, 'api', @api::text, 'roles', @roles::text[], 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')));

-- name: ApplicationRoles :many
-- Keys of the Roles an M2M Application holds on its API.
SELECT role FROM application_roles WHERE client_id = $1 AND api = $2 ORDER BY role;

-- name: ListApplications :many
-- One Application, or all of them for an empty client_id.
SELECT client_id, name, type, builtin, created_at, redirect_uris, post_logout_redirect_uris,
       COALESCE(default_api, '')::text AS default_api,
       COALESCE(extract(epoch FROM session_idle_timeout), 0)::int AS session_idle_timeout,
       COALESCE(extract(epoch FROM session_max_lifetime), 0)::int AS session_max_lifetime,
       refresh_tokens, require_role, COALESCE(webhook_url, '')::text AS webhook_url, webhook_secret_updated_at,
       COALESCE(backchannel_logout_uri, '')::text AS backchannel_logout_uri, apple_app_ids, android_apps,
       token_auth_method, jwks, login_methods, brand_name, brand_logo, brand_color
FROM applications
WHERE @client_id::text = '' OR client_id = @client_id
ORDER BY builtin DESC, created_at, client_id;

-- name: InsertApplication :exec
INSERT INTO applications (client_id, name, type, secret_hash) VALUES ($1, '', $2, $3);

-- name: UpdateApplication :execrows
-- An empty webhook_url turns the webhook off; a NULL webhook_secret keeps
-- the stored one, as does a NULL jwks. idle_secs / max_secs 0 mean the
-- default. No row either when the Logo is no longer current_logo, the one
-- read (an upload replaced it meanwhile).
UPDATE applications SET
    name = @name,
    redirect_uris = @redirect_uris,
    post_logout_redirect_uris = @post_logout_redirect_uris,
    default_api = NULLIF(@default_api::text, ''),
    session_idle_timeout = NULLIF(@idle_secs::int, 0) * interval '1 second',
    session_max_lifetime = NULLIF(@max_secs::int, 0) * interval '1 second',
    refresh_tokens = @refresh_tokens,
    require_role = @require_role,
    webhook_url = NULLIF(@webhook_url::text, ''),
    webhook_secret = CASE WHEN @webhook_url = '' THEN NULL ELSE COALESCE(sqlc.narg(webhook_secret), webhook_secret) END,
    webhook_secret_updated_at = CASE WHEN @webhook_url = '' THEN NULL
                                     WHEN sqlc.narg(webhook_secret) IS NOT NULL THEN now()
                                     ELSE webhook_secret_updated_at END,
    backchannel_logout_uri = NULLIF(@backchannel_logout_uri::text, ''),
    apple_app_ids = @apple_app_ids,
    android_apps = @android_apps,
    jwks = COALESCE(sqlc.narg(jwks), jwks),
    login_methods = sqlc.narg(login_methods),
    brand_name = sqlc.narg(brand_name),
    brand_logo = sqlc.narg(brand_logo),
    brand_color = sqlc.narg(brand_color)
WHERE client_id = @client_id AND NOT builtin
  AND COALESCE(brand_logo, '') = @current_logo::text;

-- name: SetApplicationSecret :execrows
-- Audited with who did it.
WITH put AS (
    UPDATE applications SET secret_hash = @secret_hash
    WHERE client_id = @client_id AND type <> 'public' AND token_auth_method = 'client_secret_basic' AND NOT builtin
    RETURNING client_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'application.secret_regenerated', NULL, jsonb_build_object('clientId', put.client_id, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM put;

-- name: SetTokenAuthMethod :execrows
-- Switches how the Application authenticates (ADR 0023): a secret_hash for
-- client_secret_basic, NULL for private_key_jwt, which needs a registered key.
-- Audited with who did it.
WITH put AS (
    UPDATE applications SET token_auth_method = @method, secret_hash = sqlc.narg(secret_hash)
    WHERE client_id = @client_id AND type <> 'public' AND NOT builtin
      AND (@method <> 'private_key_jwt' OR jsonb_array_length(jwks -> 'keys') > 0)
    RETURNING client_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'application.auth_method_changed', NULL, jsonb_build_object('clientId', put.client_id, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM put;

-- name: DeleteApplication :exec
-- Audited with who did it.
WITH gone AS (
    DELETE FROM applications WHERE client_id = @client_id AND NOT builtin
    RETURNING client_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'application.deleted', NULL, jsonb_build_object('clientId', gone.client_id, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: GetSettings :one
SELECT password_login, require_phone, daily_send_limit, terms_url, privacy_url, terms_version, audit_retention_days,
       admins_need_two_factor, passkey_login, open_registration, terms_url_en, privacy_url_en,
       brand_name, brand_logo, brand_color
FROM settings;

-- name: UpdateSettings :execrows
-- Changes the login policy; audited with who did it. No row when the Logo
-- is no longer current_logo, the one read (an upload replaced it meanwhile).
WITH u AS (
    UPDATE settings SET password_login = @password_login, require_phone = @require_phone,
        daily_send_limit = @daily_send_limit, terms_url = @terms_url, privacy_url = @privacy_url,
        terms_version = @terms_version, audit_retention_days = @audit_retention_days,
        admins_need_two_factor = @admins_need_two_factor, passkey_login = @passkey_login,
        open_registration = @open_registration, terms_url_en = @terms_url_en, privacy_url_en = @privacy_url_en,
        brand_name = @brand_name, brand_logo = @brand_logo, brand_color = @brand_color
    WHERE settings.brand_logo = @current_logo
    RETURNING 1
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'settings.updated', NULL, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM u;

-- name: SetUserDisabled :execrows
-- Disables or restores a User; disabling ends all their Sessions, queuing
-- a logout token for each live one (ADR 0022). Audited with who did it; no
-- row when nothing changed.
WITH changed AS (
    UPDATE users SET disabled_at = CASE WHEN @disabled::boolean THEN now() END
    WHERE users.id = @user_id AND (users.disabled_at IS NOT NULL) <> @disabled::boolean
    RETURNING users.id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', CASE WHEN @disabled::boolean THEN 'user.disabled' ELSE 'user.enabled' END, 'sub', changed.id)
    FROM changed JOIN applications a ON a.webhook_url IS NOT NULL
), ended AS (
    UPDATE sessions SET ended_at = now()
    WHERE sessions.user_id IN (SELECT changed.id FROM changed) AND @disabled::boolean AND sessions.ended_at IS NULL
    RETURNING sessions.id, sessions.user_id, sessions.lapses_at > now() AS live
), logout AS (
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
    FROM ended e JOIN session_applications sa ON sa.session_id = e.id JOIN applications a ON a.client_id = sa.client_id
    WHERE e.live AND a.backchannel_logout_uri IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT CASE WHEN @disabled::boolean THEN 'user.disabled' ELSE 'user.enabled' END AS event, changed.id, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, ''))
FROM changed;

-- name: DeleteUser :execrows
-- Deletes a User with everything of theirs (foreign keys cascade); their
-- audit events keep only the sub, with no IP or UA in any detail. Audited
-- with who did it, and queues user.deleted for every Application with a
-- webhook and a logout token for each of their live Sessions (read before
-- the cascade takes them).
WITH gone AS (
    DELETE FROM users WHERE users.id = @user_id RETURNING users.id
), scrubbed AS (
    UPDATE audit_log SET detail = detail - 'ip' - 'ua'
    WHERE audit_log.sub IN (SELECT gone.id FROM gone)
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.deleted', 'sub', gone.id)
    FROM gone JOIN applications a ON a.webhook_url IS NOT NULL
), ended AS (
    SELECT s.id, s.user_id, s.lapses_at > now() AS live
    FROM sessions s WHERE s.user_id IN (SELECT gone.id FROM gone) AND s.ended_at IS NULL
), logout AS (
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', e.user_id, 'sid', e.id)
    FROM ended e JOIN session_applications sa ON sa.session_id = e.id JOIN applications a ON a.client_id = sa.client_id
    WHERE e.live AND a.backchannel_logout_uri IS NOT NULL
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'user.deleted', gone.id, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: ListAudit :many
-- Newest first. sub matches the User an event is about or whoever did it
-- (a User's sub or an M2M Application's client_id, per detail.byType);
-- before pages by id; empty filters match all. user_identifier and
-- by_identifier are their primary Identifiers (phone, email, username),
-- empty once the User is gone (always for an Application, which has none).
SELECT id, at, event, COALESCE(sub, '')::text AS sub, detail,
       COALESCE((SELECT i.value FROM identifiers i WHERE i.user_id = audit_log.sub
                 ORDER BY array_position(ARRAY['phone', 'email', 'username'], i.kind) LIMIT 1), '')::text AS user_identifier,
       COALESCE((SELECT i.value FROM identifiers i WHERE i.user_id = audit_log.detail ->> 'by'
                 ORDER BY array_position(ARRAY['phone', 'email', 'username'], i.kind) LIMIT 1), '')::text AS by_identifier
-- sub = @sub OR by = @sub as two indexed branches: the OR alone can use
-- neither index and scans the whole log for a User with few events. The
-- unfiltered branch keeps its own filters, ORDER BY and LIMIT, so it still
-- walks the primary key backwards and stops at lim.
FROM ((SELECT * FROM audit_log a WHERE @sub::text = ''
         AND (@event::text = '' OR a.event = @event)
         AND (sqlc.narg(since)::timestamptz IS NULL OR a.at >= sqlc.narg(since))
         AND (sqlc.narg(until)::timestamptz IS NULL OR a.at < sqlc.narg(until))
         AND (@before::bigint = 0 OR a.id < @before)
       ORDER BY a.id DESC LIMIT @lim)
      UNION ALL SELECT * FROM audit_log a WHERE @sub::text <> '' AND a.sub = @sub
      UNION ALL SELECT * FROM audit_log a WHERE @sub::text <> '' AND a.detail ->> 'by' = @sub
                                          AND a.sub IS DISTINCT FROM @sub) audit_log
WHERE (@event::text = '' OR event = @event)
  AND (sqlc.narg(since)::timestamptz IS NULL OR at >= sqlc.narg(since))
  AND (sqlc.narg(until)::timestamptz IS NULL OR at < sqlc.narg(until))
  AND (@before::bigint = 0 OR id < @before)
ORDER BY id DESC
LIMIT @lim;

-- name: Overview :one
SELECT (SELECT count(*) FROM users) AS users,
       (SELECT count(*) FROM sessions WHERE auth_time >= date_trunc('day', now())) AS logins_today,
       (SELECT count(*) FROM sessions WHERE ended_at IS NULL AND lapses_at > now()) AS live_sessions,
       (SELECT count(*) FROM applications) AS applications,
       (SELECT count(*) FROM sends WHERE sent_at >= now() - make_interval(secs => @day_secs::int)) AS sends_last_day,
       (SELECT daily_send_limit FROM settings) AS daily_send_limit;

-- name: SetInstanceLogo :exec
-- Replaces the instance's Logo; audited with who did it.
WITH u AS (UPDATE settings SET brand_logo = @logo)
INSERT INTO audit_log (event, sub, detail)
VALUES ('settings.updated', NULL, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, '')));

-- name: SetApplicationLogo :execrows
-- Replaces an Application's own Logo; NULL follows the instance's.
UPDATE applications SET brand_logo = sqlc.narg(logo)
WHERE client_id = @client_id AND NOT builtin AND type <> 'm2m';

-- name: DeleteUnusedLogos :exec
-- Deletes the Logo blobs no brand names any more: the one a new upload,
-- a cleared Logo or a deleted Application left behind.
DELETE FROM blobs WHERE key LIKE 'brand/%'
    AND key NOT IN (SELECT brand_logo FROM settings
                    UNION ALL SELECT brand_logo FROM applications WHERE brand_logo IS NOT NULL);

-- name: InstanceLogo :one
-- The instance's Logo: a save checks the Logo it sends back against this,
-- and writes only while it is still current (UpdateSettings).
SELECT brand_logo FROM settings;

-- name: ApplicationLogo :one
-- An Application's own Logo ('' for none), checked as InstanceLogo.
SELECT COALESCE(brand_logo, '')::text FROM applications WHERE client_id = @client_id;
