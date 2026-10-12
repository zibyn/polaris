-- +goose Up

-- 待激活 (ADR 0016): a User an admin created, who has yet to replace the
-- initial password with one of their own. They can sign in with it, but get
-- no authorization code — hence no token — until they do, so Applications
-- never see this state: no claim, no scope, no change to the ID token.
--
-- 待激活 = pending 且未禁用; 禁用永远优先, because a disabled User cannot
-- sign in at all. SetUserDisabled 只在两者之间切换, 不动这一列.
ALTER TABLE users ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('pending', 'active'));

-- The console lists and filters by 待激活.
CREATE INDEX ON users (status) WHERE status = 'pending';

-- +goose Down

DROP INDEX users_status_idx;
ALTER TABLE users DROP COLUMN status;
