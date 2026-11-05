-- +goose Up

-- DeleteOldSessions ORs ended_at with lapses_at; without this the OR cannot
-- use lapses_at's index either and scans every Session.
CREATE INDEX sessions_ended_at_idx ON sessions (ended_at) WHERE ended_at IS NOT NULL;
-- ListUsers' order: an unfiltered page walks this and stops at the limit.
CREATE INDEX users_created_at_id_idx ON users (created_at DESC, id);
-- Deleting Sessions cascades here, one scan per Session without it.
CREATE INDEX provider_logins_session_id_idx ON provider_logins (session_id);

-- +goose Down

DROP INDEX provider_logins_session_id_idx;
DROP INDEX users_created_at_id_idx;
DROP INDEX sessions_ended_at_idx;
