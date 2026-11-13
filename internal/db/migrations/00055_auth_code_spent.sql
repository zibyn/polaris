-- +goose Up

-- A redeemed code keeps its hash so a reuse still finds the grant and
-- revokes it (RFC 6749 §4.1.2); this flag stops it redeeming again.
ALTER TABLE oidc_grants ADD COLUMN auth_code_spent boolean NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE oidc_grants DROP COLUMN auth_code_spent;
