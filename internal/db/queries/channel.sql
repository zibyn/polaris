-- name: ListChannels :many
SELECT c.kind, c.plugin, c.config, c.updated_at,
       COALESCE((SELECT jsonb_object_agg(s.field, s.updated_at) FROM channel_secrets s WHERE s.kind = c.kind),
                '{}')::jsonb AS secrets
FROM channels c
ORDER BY c.kind;

-- name: GetChannel :one
SELECT plugin, config, version FROM channels WHERE kind = $1;

-- name: ChannelSecrets :many
SELECT field, value FROM channel_secrets WHERE kind = $1;

-- name: SaveChannel :execrows
-- Saves kind if it is still at version, the one read (0: there was none);
-- no row when another save got there first (ADR 0030).
INSERT INTO channels (kind, plugin, config, version) VALUES (@kind, @plugin, @config, 1)
ON CONFLICT (kind) DO UPDATE SET plugin = excluded.plugin, config = excluded.config, updated_at = now(),
    version = channels.version + 1
WHERE channels.version = @version;

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
SELECT 'channel.deleted', NULL, jsonb_build_object('kind', gone.kind, 'by', @by_id::text, 'byType', NULLIF(@by_type::text, '')) FROM gone;

-- name: ChannelKinds :many
SELECT kind FROM channels;
