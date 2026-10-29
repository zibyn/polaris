-- +goose Up

-- 寿命上限 (docs/spec/protocol.md#session): a Session also dies max_lifetime
-- after auth_time, however active it is. Like idle_timeout, it is the
-- starting Application's setting (NULL: the default) copied onto the Session.
-- Existing Sessions get the default of their kind; those already past it end
-- on deploy.
ALTER TABLE applications ADD COLUMN session_max_lifetime interval;
ALTER TABLE sessions ADD COLUMN max_lifetime interval;
UPDATE sessions SET max_lifetime = CASE WHEN id_hash IS NULL THEN interval '180 days' ELSE interval '90 days' END;
ALTER TABLE sessions ALTER COLUMN max_lifetime SET NOT NULL;

CREATE OR REPLACE VIEW live_sessions AS
SELECT id FROM sessions
WHERE ended_at IS NULL AND last_seen_at + idle_timeout > now() AND auth_time + max_lifetime > now();

-- Reaching the cap is a lapse too: deleting such a Session sends no logout.
DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND OLD.last_seen_at + OLD.idle_timeout > now()
                       AND OLD.auth_time + OLD.max_lifetime > now())
    EXECUTE FUNCTION queue_logout_tokens();

-- +goose Down

DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND OLD.last_seen_at + OLD.idle_timeout > now())
    EXECUTE FUNCTION queue_logout_tokens();
CREATE OR REPLACE VIEW live_sessions AS
SELECT id FROM sessions WHERE ended_at IS NULL AND last_seen_at + idle_timeout > now();
ALTER TABLE sessions DROP COLUMN max_lifetime;
ALTER TABLE applications DROP COLUMN session_max_lifetime;
