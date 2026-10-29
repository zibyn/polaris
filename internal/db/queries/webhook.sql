-- name: ClaimDeliveries :many
-- Due deliveries, each held back for 5 minutes while it is being sent so
-- that no other replica sends it too.
UPDATE webhook_deliveries AS d SET next_at = now() + interval '5 minutes', attempts = d.attempts + 1
FROM applications a
WHERE a.client_id = d.client_id
  AND d.id IN (SELECT w.id FROM webhook_deliveries w WHERE w.next_at <= now() ORDER BY w.next_at LIMIT 20 FOR UPDATE SKIP LOCKED)
RETURNING d.id, d.client_id, d.kind, d.payload, d.attempts,
          COALESCE(CASE d.kind WHEN 'logout' THEN a.backchannel_logout_uri ELSE a.webhook_url END, '')::text AS url,
          a.webhook_secret AS secret;

-- name: DeleteDelivery :exec
DELETE FROM webhook_deliveries WHERE id = $1;

-- name: RetryDelivery :exec
UPDATE webhook_deliveries SET next_at = now() + make_interval(secs => @wait_secs::integer) WHERE id = @id;
