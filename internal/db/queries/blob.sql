-- name: PutBlob :exec
INSERT INTO blobs (key, content_type, bytes) VALUES ($1, $2, $3)
ON CONFLICT (key) DO UPDATE SET content_type = EXCLUDED.content_type, bytes = EXCLUDED.bytes;

-- name: GetBlob :one
SELECT content_type, bytes FROM blobs WHERE key = $1;

-- name: DeleteBlob :exec
DELETE FROM blobs WHERE key = $1;
