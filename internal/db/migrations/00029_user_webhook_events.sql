-- +goose Up

-- The webhook deliveries of one thin User event (ADR 0022,
-- docs/spec/protocol.md#webhook): one per Application with a webhook,
-- carrying only the sub and, for user.updated, which kinds of thing changed.
-- A query queues them with INSERT INTO webhook_deliveries ... SELECT * FROM
-- user_event(...), so they share its transaction.
-- +goose StatementBegin
CREATE FUNCTION user_event(event text, uid text, changed text[] DEFAULT NULL)
    RETURNS TABLE (client_id text, payload jsonb)
    STABLE LANGUAGE sql AS $$
    SELECT a.client_id, jsonb_build_object(
        'type', event,
        'timestamp', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'data', jsonb_build_object('sub', uid) || CASE WHEN changed IS NULL THEN '{}'::jsonb
                                                       ELSE jsonb_build_object('changed', changed) END)
    FROM applications a WHERE a.webhook_url IS NOT NULL
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION user_event(text, text, text[]);
