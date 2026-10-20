-- +goose Up

-- The account center (docs/spec/consoles.md#账号中心单页长滚动): a built-in
-- Application whose access tokens are for the built-in Account API, where a
-- User manages their own account. Redirect URIs are wired up at start.
INSERT INTO apis (identifier, name, builtin)
VALUES ('urn:polaris:account-api', 'Account API', true);
INSERT INTO applications (client_id, name, type, default_api, builtin)
VALUES ('polaris-account', 'Polaris 账号中心', 'public', 'urn:polaris:account-api', true);

-- user.deleted webhook deliveries waiting to go out
-- (docs/spec/protocol.md#webhook); each retry waits longer, until it is
-- dropped. id is the webhook-id, the same on every retry.
CREATE TABLE webhook_deliveries (
    id         text PRIMARY KEY DEFAULT replace(gen_random_uuid()::text, '-', ''),
    client_id  text NOT NULL REFERENCES applications (client_id) ON DELETE CASCADE,
    payload    jsonb NOT NULL,
    attempts   integer NOT NULL DEFAULT 0,
    next_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON webhook_deliveries (next_at);
