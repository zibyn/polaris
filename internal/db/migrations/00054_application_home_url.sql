-- +goose Up

-- 首页地址: where the account center links back to (ADR 0034); NULL for none.
ALTER TABLE applications ADD COLUMN home_url text;

-- +goose Down

ALTER TABLE applications DROP COLUMN home_url;
