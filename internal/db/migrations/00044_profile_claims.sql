-- +goose Up

-- 用户资料 grows to the OIDC standard claims (ADR 0029): every profile claim
-- Polaris has no column for, and the address, as the claims' own JSON; plus
-- when any of 用户资料 last changed, for updated_at. Checked in Go.
ALTER TABLE users
    ADD COLUMN profile jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN profile_updated_at timestamptz;

-- +goose Down

ALTER TABLE users DROP COLUMN profile_updated_at, DROP COLUMN profile;
