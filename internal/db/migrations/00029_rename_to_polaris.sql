-- +goose Up

-- Rename the built-in OAuth identifiers from stars-auth to polaris. Values
-- referenced by other tables are copied rather than updated in place: roles,
-- permissions and application_roles reference the API identifier by value,
-- and the old rows must stay until every child has moved.
--
-- Every Session and Grant is dropped: tokens minted before the rename carry
-- the old audience and cannot be refreshed against the new one.

INSERT INTO apis (identifier, name, builtin, created_at)
SELECT 'urn:polaris:management-api', name, builtin, created_at
FROM apis WHERE identifier = 'urn:stars-auth:management-api';
INSERT INTO apis (identifier, name, builtin, created_at)
SELECT 'urn:polaris:account-api', name, builtin, created_at
FROM apis WHERE identifier = 'urn:stars-auth:account-api';

INSERT INTO roles (api, key, name, builtin)
SELECT 'urn:polaris:management-api', key, name, builtin
FROM roles WHERE api = 'urn:stars-auth:management-api';
INSERT INTO permissions (api, key, name, builtin)
SELECT 'urn:polaris:management-api', key, name, builtin
FROM permissions WHERE api = 'urn:stars-auth:management-api';

INSERT INTO role_permissions (api, role, permission)
SELECT 'urn:polaris:management-api', role, permission
FROM role_permissions WHERE api = 'urn:stars-auth:management-api';
INSERT INTO user_roles (user_id, api, role)
SELECT user_id, 'urn:polaris:management-api', role
FROM user_roles WHERE api = 'urn:stars-auth:management-api';
INSERT INTO application_roles (client_id, api, role)
SELECT client_id, 'urn:polaris:management-api', role
FROM application_roles WHERE api = 'urn:stars-auth:management-api';

UPDATE applications SET default_api = 'urn:polaris:management-api'
WHERE default_api = 'urn:stars-auth:management-api';
UPDATE applications SET default_api = 'urn:polaris:account-api'
WHERE default_api = 'urn:stars-auth:account-api';

INSERT INTO applications (
    client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, default_api, session_idle_timeout,
    builtin, created_at, refresh_tokens, webhook_url, webhook_secret,
    webhook_secret_updated_at, apple_app_ids, android_apps
)
SELECT 'polaris-console', name, type, secret_hash, redirect_uris,
       post_logout_redirect_uris, default_api, session_idle_timeout,
       builtin, created_at, refresh_tokens, webhook_url, webhook_secret,
       webhook_secret_updated_at, apple_app_ids, android_apps
FROM applications WHERE client_id = 'stars-auth-console';
INSERT INTO applications (
    client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, default_api, session_idle_timeout,
    builtin, created_at, refresh_tokens, webhook_url, webhook_secret,
    webhook_secret_updated_at, apple_app_ids, android_apps
)
SELECT 'polaris-account', name, type, secret_hash, redirect_uris,
       post_logout_redirect_uris, default_api, session_idle_timeout,
       builtin, created_at, refresh_tokens, webhook_url, webhook_secret,
       webhook_secret_updated_at, apple_app_ids, android_apps
FROM applications WHERE client_id = 'stars-auth-account';

UPDATE application_roles SET client_id = 'polaris-console'
WHERE client_id = 'stars-auth-console';
UPDATE application_roles SET client_id = 'polaris-account'
WHERE client_id = 'stars-auth-account';
UPDATE webhook_deliveries SET client_id = 'polaris-console'
WHERE client_id = 'stars-auth-console';
UPDATE webhook_deliveries SET client_id = 'polaris-account'
WHERE client_id = 'stars-auth-account';
UPDATE oidc_challenge_sessions SET client_id = 'polaris-console'
WHERE client_id = 'stars-auth-console';
UPDATE oidc_challenge_sessions SET client_id = 'polaris-account'
WHERE client_id = 'stars-auth-account';
UPDATE sessions SET client_id = 'polaris-console'
WHERE client_id = 'stars-auth-console';
UPDATE sessions SET client_id = 'polaris-account'
WHERE client_id = 'stars-auth-account';

UPDATE audit_log SET detail = jsonb_set(detail, '{by}', '"polaris-console"')
WHERE detail ->> 'by' = 'stars-auth-console';
UPDATE audit_log SET detail = jsonb_set(detail, '{by}', '"polaris-account"')
WHERE detail ->> 'by' = 'stars-auth-account';

DELETE FROM applications WHERE client_id IN ('stars-auth-console', 'stars-auth-account');

-- Tokens, auth codes and browser Sessions all predate the rename.
DELETE FROM oidc_grants;
DELETE FROM oidc_authn_sessions;
DELETE FROM oidc_challenge_sessions;
DELETE FROM sessions;

DELETE FROM role_permissions WHERE api = 'urn:stars-auth:management-api';
DELETE FROM user_roles WHERE api = 'urn:stars-auth:management-api';
DELETE FROM application_roles WHERE api = 'urn:stars-auth:management-api';
DELETE FROM roles WHERE api = 'urn:stars-auth:management-api';
DELETE FROM permissions WHERE api = 'urn:stars-auth:management-api';
DELETE FROM apis WHERE identifier IN ('urn:stars-auth:management-api', 'urn:stars-auth:account-api');
