-- name: ClaimDeliveries :many
-- Due deliveries, batch at most, each held back for hold_secs while it is being sent so
-- that no other replica sends it too.
UPDATE webhook_deliveries AS d SET next_at = now() + make_interval(secs => @hold_secs::int), attempts = d.attempts + 1
FROM applications a
WHERE a.client_id = d.client_id
  AND d.id IN (SELECT w.id FROM webhook_deliveries w WHERE w.next_at <= now() ORDER BY w.next_at LIMIT @batch::int FOR UPDATE SKIP LOCKED)
RETURNING d.id, d.client_id, d.kind, d.payload, d.attempts, d.created_at,
          COALESCE(CASE d.kind WHEN 'logout' THEN a.backchannel_logout_uri ELSE a.webhook_url END, '')::text AS url,
          a.webhook_secret AS secret;

-- name: DeleteDelivery :exec
DELETE FROM webhook_deliveries WHERE id = $1;

-- name: RetryDelivery :exec
UPDATE webhook_deliveries SET next_at = now() + make_interval(secs => @wait_secs::integer) WHERE id = @id;
