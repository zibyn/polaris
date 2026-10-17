-- +goose Up

-- 待激活 is one predicate: status = 'pending' AND disabled_at IS NULL
-- (ADR 0016; disabled wins). A generated column keeps that definition in one
-- place, so every query that asks the question reads the same answer.
ALTER TABLE users ADD COLUMN pending boolean
    GENERATED ALWAYS AS (status = 'pending' AND disabled_at IS NULL) STORED NOT NULL;

-- The console filtered 待激活 by status; it reads pending now.
DROP INDEX users_status_idx;
CREATE INDEX ON users (pending) WHERE pending;

-- +goose Down

DROP INDEX users_pending_idx;
CREATE INDEX ON users (status) WHERE status = 'pending';
ALTER TABLE users DROP COLUMN pending;
