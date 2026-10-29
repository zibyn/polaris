-- +goose Up

-- When a Session lapses: idle (闲置时长) or at its 寿命上限, whichever comes
-- first (docs/spec/protocol.md#session). One definition, every caller.
-- +goose StatementBegin
CREATE FUNCTION session_lapses_at(s sessions) RETURNS timestamptz
    STABLE LANGUAGE sql AS $$
    SELECT LEAST(s.last_seen_at + s.idle_timeout, s.auth_time + s.max_lifetime)
$$;
-- +goose StatementEnd

CREATE OR REPLACE VIEW live_sessions AS
SELECT id FROM sessions WHERE ended_at IS NULL AND session_lapses_at(sessions) > now();

DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND session_lapses_at(OLD) > now())
    EXECUTE FUNCTION queue_logout_tokens();
DROP TRIGGER queue_logout_tokens_on_end ON sessions;
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL AND session_lapses_at(OLD) > now())
    EXECUTE FUNCTION queue_logout_tokens();

COMMENT ON COLUMN sessions.idle_timeout IS
    'The default is a browser Session''s, only for direct INSERTs (tests); oidcstore.SessionDefaults decides.';
COMMENT ON COLUMN sessions.max_lifetime IS
    'The default is a browser Session''s, only for direct INSERTs (tests); oidcstore.SessionDefaults decides.';

-- +goose Down

COMMENT ON COLUMN sessions.max_lifetime IS NULL;
COMMENT ON COLUMN sessions.idle_timeout IS NULL;
DROP TRIGGER queue_logout_tokens_on_end ON sessions;
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL
                       AND OLD.last_seen_at + OLD.idle_timeout > now()
                       AND OLD.auth_time + OLD.max_lifetime > now())
    EXECUTE FUNCTION queue_logout_tokens();
DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND OLD.last_seen_at + OLD.idle_timeout > now()
                       AND OLD.auth_time + OLD.max_lifetime > now())
    EXECUTE FUNCTION queue_logout_tokens();
CREATE OR REPLACE VIEW live_sessions AS
SELECT id FROM sessions
WHERE ended_at IS NULL AND last_seen_at + idle_timeout > now() AND auth_time + max_lifetime > now();
DROP FUNCTION session_lapses_at(sessions);
