-- +goose Up

-- A webhook delivery keeps the event's facts (type, sub, changed) and when
-- it happened; the sender writes the payload from them (ADR 0030), not a
-- function in the database.
ALTER TABLE webhook_deliveries ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
UPDATE webhook_deliveries
SET created_at = (payload ->> 'timestamp')::timestamptz,
    payload = jsonb_build_object('type', payload ->> 'type', 'sub', payload -> 'data' ->> 'sub')
              || CASE WHEN payload -> 'data' ? 'changed' THEN jsonb_build_object('changed', payload -> 'data' -> 'changed') ELSE '{}' END
WHERE kind = 'webhook';
DROP FUNCTION user_event(text, text, text[]);

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION user_event(event text, uid text, changed text[] DEFAULT NULL) RETURNS TABLE (client_id text, payload jsonb)
LANGUAGE sql STABLE AS $$
    SELECT a.client_id, jsonb_build_object(
        'type', event,
        'timestamp', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'data', jsonb_build_object('sub', uid) || CASE WHEN changed IS NULL THEN '{}'::jsonb
                                                       ELSE jsonb_build_object('changed', changed) END)
    FROM applications a WHERE a.webhook_url IS NOT NULL
$$;
-- +goose StatementEnd
UPDATE webhook_deliveries
SET payload = jsonb_build_object('type', payload ->> 'type',
        'timestamp', to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'data', jsonb_build_object('sub', payload ->> 'sub') || CASE WHEN payload ? 'changed'
                THEN jsonb_build_object('changed', payload -> 'changed') ELSE '{}' END)
WHERE kind = 'webhook';
ALTER TABLE webhook_deliveries DROP COLUMN created_at;
