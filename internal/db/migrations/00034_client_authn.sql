-- +goose Up

-- 客户端认证方式二选一,Application 公钥只按值登记 (ADR 0023).
ALTER TABLE applications
    ADD COLUMN token_auth_method text NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_auth_method IN ('client_secret_basic', 'private_key_jwt')),
    ADD COLUMN jwks jsonb NOT NULL DEFAULT '{"keys": []}',
    DROP CONSTRAINT applications_check,
    -- public 没有 client secret;其余的有,除非改用私钥签名。
    ADD CONSTRAINT applications_check CHECK (
        (type <> 'public' AND token_auth_method = 'client_secret_basic') = (secret_hash IS NOT NULL)),
    -- 私钥签名要有公钥可验。
    ADD CONSTRAINT applications_jwks_check CHECK (
        token_auth_method <> 'private_key_jwt' OR (type <> 'public' AND jsonb_array_length(jwks -> 'keys') > 0));

-- +goose Down

ALTER TABLE applications
    DROP CONSTRAINT applications_jwks_check,
    DROP CONSTRAINT applications_check,
    DROP COLUMN jwks,
    DROP COLUMN token_auth_method,
    ADD CONSTRAINT applications_check CHECK ((type <> 'public') = (secret_hash IS NOT NULL));
