-- +goose Up

-- 两步验证或 Passkey is twofactor.Satisfied in Go (ADR 0030); the queries
-- read the facts it weighs.
DROP FUNCTION two_factor_satisfied(text);
DROP FUNCTION totp_confirmed(text);
DROP FUNCTION has_passkey(text);

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION has_passkey(uid text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = uid)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION totp_confirmed(uid text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM totp_credentials t WHERE t.user_id = uid AND t.confirmed_at IS NOT NULL)
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION two_factor_satisfied(uid text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT totp_confirmed(uid) OR ((SELECT passkey_login FROM settings) AND has_passkey(uid))
$$;
-- +goose StatementEnd
