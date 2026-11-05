-- +goose Up

-- When a Session lapses is a column the queries that move last_seen_at or
-- auth_time keep up to date (ADR 0030), not a function every reader calls:
-- the rule lives in the writers, and the column can be indexed.
ALTER TABLE sessions ADD COLUMN lapses_at timestamptz;
UPDATE sessions SET lapses_at = LEAST(last_seen_at + idle_timeout, auth_time + max_lifetime);
ALTER TABLE sessions ALTER COLUMN lapses_at SET NOT NULL;
CREATE INDEX sessions_lapses_at_idx ON sessions (lapses_at);
-- Only the cleanup filtered on last_seen_at; it goes by lapses_at now.
DROP INDEX sessions_last_seen_at_idx;
DROP VIEW live_sessions;
DROP FUNCTION session_lapses_at(sessions);

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION session_lapses_at(s sessions) RETURNS timestamptz LANGUAGE sql STABLE AS $$
    SELECT LEAST(s.last_seen_at + s.idle_timeout, s.auth_time + s.max_lifetime)
$$;
-- +goose StatementEnd
CREATE VIEW live_sessions AS
SELECT id FROM sessions WHERE ended_at IS NULL AND session_lapses_at(sessions) > now();
CREATE INDEX sessions_last_seen_at_idx ON sessions (last_seen_at);
DROP INDEX sessions_lapses_at_idx;
ALTER TABLE sessions DROP COLUMN lapses_at;
