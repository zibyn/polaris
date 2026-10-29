-- +goose Up

-- 用户资料 (ADR 0020): a nickname, and the key of the avatar's blob.
ALTER TABLE users ADD COLUMN nickname text, ADD COLUMN avatar text;

-- The PG backend of the blob store: bytes by key, nothing about what they
-- are for.
CREATE TABLE blobs (
    key          text PRIMARY KEY,
    content_type text NOT NULL,
    bytes        bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down

DROP TABLE blobs;
ALTER TABLE users DROP COLUMN avatar, DROP COLUMN nickname;
