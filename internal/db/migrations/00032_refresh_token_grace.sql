-- +goose Up

-- When a rotation spent the token: the one spent last on its grant gets a
-- grace window (ADR 0019). Existing rows count as long spent.
ALTER TABLE oidc_spent_refresh_tokens ADD COLUMN spent_at timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE oidc_spent_refresh_tokens ALTER COLUMN spent_at SET DEFAULT now();
CREATE INDEX ON oidc_spent_refresh_tokens (grant_id, spent_at);
DROP INDEX oidc_spent_refresh_tokens_grant_id_idx;

-- +goose Down

CREATE INDEX ON oidc_spent_refresh_tokens (grant_id);
DROP INDEX oidc_spent_refresh_tokens_grant_id_spent_at_idx;
ALTER TABLE oidc_spent_refresh_tokens DROP COLUMN spent_at;
