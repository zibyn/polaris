-- name: ListProviders :many
-- only_login_path counts the bound Users with no other way to sign in
-- (docs/spec/identity.md#不变式); one at a disabled Provider is none.
SELECT p.id, p.type, p.name, p.enabled, p.config, p.created_at,
       COALESCE((SELECT jsonb_object_agg(s.field, s.updated_at) FROM provider_secrets s WHERE s.provider = p.id),
                '{}')::jsonb AS secrets,
       (SELECT count(*) FROM external_identities e WHERE e.provider = p.id) AS bound,
       (SELECT count(*) FROM external_identities e
        WHERE e.provider = p.id
          AND NOT EXISTS (SELECT 1 FROM external_identities o JOIN providers op ON op.id = o.provider
                          WHERE o.user_id = e.user_id AND o.provider <> p.id AND op.enabled)
          AND NOT EXISTS (SELECT 1 FROM identifiers i WHERE i.user_id = e.user_id
                          AND (i.kind <> 'username' OR EXISTS (SELECT 1 FROM passwords pw WHERE pw.user_id = e.user_id)))
       ) AS only_login_path
FROM providers p
ORDER BY p.created_at;

-- name: GetProvider :one
SELECT type, name, enabled, config FROM providers WHERE id = $1;

-- name: GetProviderForUpdate :one
SELECT type, config FROM providers WHERE id = $1 FOR UPDATE;

-- name: EnabledProviders :many
SELECT id, type, name FROM providers WHERE enabled ORDER BY created_at;

-- name: InsertProvider :exec
INSERT INTO providers (id, type, name, config) VALUES ($1, $2, $3, $4);

-- name: UpdateProvider :exec
UPDATE providers SET name = $2, config = $3 WHERE id = $1;

-- name: SetProviderEnabled :execrows
-- Audited with who did it.
WITH put AS (
    UPDATE providers SET enabled = @enabled WHERE providers.id = @id RETURNING providers.id
)
INSERT INTO audit_log (event, sub, detail)
SELECT CASE WHEN @enabled::boolean THEN 'provider.enabled' ELSE 'provider.disabled' END, NULL,
       jsonb_build_object('id', put.id, 'by', @by::text)
FROM put;

-- name: DeleteProvider :execrows
-- Audited with who did it.
WITH gone AS (
    DELETE FROM providers WHERE providers.id = @id RETURNING providers.id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'provider.deleted', NULL, jsonb_build_object('id', gone.id, 'by', @by::text) FROM gone;

-- name: ProviderSecrets :many
SELECT field, value FROM provider_secrets WHERE provider = $1;

-- name: PutProviderSecret :exec
INSERT INTO provider_secrets (provider, field, value) VALUES ($1, $2, $3)
ON CONFLICT (provider, field) DO UPDATE SET value = excluded.value, updated_at = now();

-- name: InsertProviderLogin :exec
INSERT INTO provider_logins (state_hash, provider, nonce, verifier, authn_session, binder_hash) VALUES ($1, $2, $3, $4, $5, $6);

-- name: InsertProviderAccountLogin :exec
INSERT INTO provider_logins (state_hash, provider, nonce, verifier, authn_session, session_id, reauth)
VALUES ($1, $2, $3, $4, '', $5, $6);

-- name: TakeProviderLogin :one
DELETE FROM provider_logins WHERE state_hash = $1 AND provider = $2 AND expires_at > now()
RETURNING nonce, verifier, authn_session, binder_hash, session_id, reauth, created_at;

-- name: LiveSessionUser :one
SELECT s.user_id FROM sessions s WHERE s.id = $1 AND s.id IN (SELECT l.id FROM live_sessions l);

-- name: UserByExternalIdentity :one
SELECT e.user_id, (u.disabled_at IS NOT NULL)::boolean AS disabled
FROM external_identities e JOIN users u ON u.id = e.user_id
WHERE e.provider = $1 AND e.subject = $2;

-- name: AddExternalIdentity :exec
INSERT INTO external_identities (provider, subject, user_id, token) VALUES ($1, $2, $3, $4);

-- name: SetExternalIdentityToken :exec
UPDATE external_identities SET token = $3 WHERE provider = $1 AND subject = $2;

-- name: UserExternalIdentities :many
SELECT provider, subject, token FROM external_identities WHERE user_id = $1;

-- name: BindExternalIdentity :exec
WITH added AS (
    INSERT INTO external_identities (provider, subject, user_id, token) VALUES (@provider, @subject, @user_id, @token)
    RETURNING provider, user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'external_identity.added', user_id, jsonb_build_object('provider', provider, 'by', user_id) FROM added;

-- name: ExternalIdentitySubject :one
SELECT subject FROM external_identities WHERE user_id = $1 AND provider = $2;

-- name: ExternalIdentities :many
-- A User's External Identities, in the login page's order of their Providers.
SELECT e.provider, p.name, p.enabled, e.created_at
FROM external_identities e JOIN providers p ON p.id = e.provider
WHERE e.user_id = $1
ORDER BY p.created_at;

-- name: RemoveExternalIdentity :one
-- Audited as done by by.
WITH gone AS (
    DELETE FROM external_identities WHERE user_id = @user_id AND provider = @provider RETURNING user_id, provider, subject, token
), audited AS (
    INSERT INTO audit_log (event, sub, detail)
    SELECT 'external_identity.removed', user_id, jsonb_build_object('provider', provider, 'by', @by::text) FROM gone
)
SELECT subject, token FROM gone;
