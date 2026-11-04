-- +goose Up

-- The English 用户协议 and 隐私政策 the English hosted pages link to
-- (ADR 0028); empty falls back to the Chinese ones. One terms_version
-- covers both languages.
ALTER TABLE settings
    ADD COLUMN terms_url_en text NOT NULL DEFAULT '',
    ADD COLUMN privacy_url_en text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE settings DROP COLUMN privacy_url_en, DROP COLUMN terms_url_en;
