-- +goose Up

-- Optimistic concurrency instead of row and table locks (ADR 0030). A save
-- names the version it read and bumps it; touching no row is the conflict.
ALTER TABLE channels ADD COLUMN version bigint NOT NULL DEFAULT 1;
ALTER TABLE channels ALTER COLUMN version DROP DEFAULT;
ALTER TABLE providers ADD COLUMN version bigint NOT NULL DEFAULT 1;
ALTER TABLE providers ALTER COLUMN version DROP DEFAULT;

-- Each signing key succeeds the one before it: two replicas that rotate at
-- once both name the same generation, and the unique key keeps one.
ALTER TABLE signing_keys ADD COLUMN generation bigint;
UPDATE signing_keys k SET generation = n.g
FROM (SELECT kid, row_number() OVER (ORDER BY created_at, kid) AS g FROM signing_keys) n
WHERE n.kid = k.kid;
ALTER TABLE signing_keys ALTER COLUMN generation SET NOT NULL,
    ADD CONSTRAINT signing_keys_generation_key UNIQUE (generation);

-- +goose Down

ALTER TABLE signing_keys DROP COLUMN generation;
ALTER TABLE providers DROP COLUMN version;
ALTER TABLE channels DROP COLUMN version;
