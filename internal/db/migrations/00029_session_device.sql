-- +goose Up

-- The device a Session was last used from (docs/spec/consoles.md): the
-- client IP and the raw User-Agent, cut to 512 bytes. Only the latest, no
-- history; NULL for a Session from before this.
ALTER TABLE sessions ADD COLUMN ip text, ADD COLUMN user_agent text;

-- +goose Down

ALTER TABLE sessions DROP COLUMN ip, DROP COLUMN user_agent;
