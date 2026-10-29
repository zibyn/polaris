-- +goose Up

-- 开放注册 (ADR 0021): off, logging in no longer signs a stranger up. On by
-- default, as before.
ALTER TABLE settings ADD COLUMN open_registration boolean NOT NULL DEFAULT true;
