-- +goose Up

-- JWT IDs already seen in DPoP proofs and client assertions, so each is good
-- once. Kept until its JWT can no longer be valid, then dropped by the hourly
-- cleanup.
CREATE TABLE oidc_jtis (
    jti        text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX ON oidc_jtis (expires_at);

-- +goose Down

DROP TABLE oidc_jtis;
