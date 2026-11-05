-- +goose Up

-- Logout tokens are queued by the queries that end a Session or delete its
-- User (ADR 0030), not by triggers on sessions.
DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
DROP TRIGGER queue_logout_tokens_on_end ON sessions;
DROP FUNCTION queue_logout_tokens();

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION queue_logout_tokens() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', OLD.user_id, 'sid', OLD.id)
    FROM session_applications sa JOIN applications a USING (client_id)
    WHERE sa.session_id = OLD.id AND a.backchannel_logout_uri IS NOT NULL;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND session_lapses_at(OLD) > now())
    EXECUTE FUNCTION queue_logout_tokens();
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL AND session_lapses_at(OLD) > now())
    EXECUTE FUNCTION queue_logout_tokens();
