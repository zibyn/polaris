-- name: ListChannels :many
SELECT c.kind, c.plugin, c.config, c.updated_at,
       COALESCE((SELECT jsonb_object_agg(s.field, s.updated_at) FROM channel_secrets s WHERE s.kind = c.kind),
                '{}')::jsonb AS secrets
FROM channels c
ORDER BY c.kind;

-- name: GetChannel :one
SELECT plugin, config FROM channels WHERE kind = $1;

-- name: LockChannels :exec
-- Serialises writers, including two first saves of a kind (no row to lock yet).
LOCK TABLE channels IN SHARE ROW EXCLUSIVE MODE;

-- name: ChannelSecrets :many
SELECT field, value FROM channel_secrets WHERE kind = $1;

-- name: PutChannel :exec
INSERT INTO channels (kind, plugin, config) VALUES ($1, $2, $3)
ON CONFLICT (kind) DO UPDATE SET plugin = excluded.plugin, config = excluded.config, updated_at = now();

-- name: PutChannelSecret :exec
INSERT INTO channel_secrets (kind, field, value) VALUES ($1, $2, $3)
ON CONFLICT (kind, field) DO UPDATE SET value = excluded.value, updated_at = now();

-- name: DeleteChannelSecrets :exec
DELETE FROM channel_secrets WHERE kind = $1;

-- name: DeleteChannel :exec
-- Audited with who did it, when there was one to delete.
WITH gone AS (
    DELETE FROM channels WHERE kind = @kind RETURNING kind
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'channel.deleted', NULL, jsonb_build_object('kind', gone.kind, 'by', @by::text) FROM gone;

-- name: ChannelKinds :many
SELECT kind FROM channels;
