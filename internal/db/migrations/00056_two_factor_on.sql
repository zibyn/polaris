-- +goose Up

-- 两步验证 is on while the User has a row here, since enabled_at; no longer
-- read off a confirmed TOTP, which is now one second factor among others
-- (#197). Every User with a confirmed TOTP had it on, so keeps it.
CREATE TABLE two_factor (
    user_id    text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    enabled_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO two_factor (user_id, enabled_at)
SELECT user_id, confirmed_at FROM totp_credentials WHERE confirmed_at IS NOT NULL;

-- +goose Down
DROP TABLE two_factor;
