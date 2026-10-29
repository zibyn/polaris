-- +goose Up

-- Setting ended_at on a Session that already lapsed (idle or 寿命上限) sends
-- no logout either: like the delete trigger, nobody ended a live Session.
DROP TRIGGER queue_logout_tokens_on_end ON sessions;
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL
                       AND OLD.last_seen_at + OLD.idle_timeout > now()
                       AND OLD.auth_time + OLD.max_lifetime > now())
    EXECUTE FUNCTION queue_logout_tokens();

-- +goose Down

DROP TRIGGER queue_logout_tokens_on_end ON sessions;
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL)
    EXECUTE FUNCTION queue_logout_tokens();
