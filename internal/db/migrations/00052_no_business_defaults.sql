-- +goose Up

-- How long a Provider sign-in may take and a Session's idle timeout and
-- lifespan cap come from Go (ADR 0030); without a default, a write that
-- leaves one out fails instead of taking a value nobody chose.
ALTER TABLE provider_logins ALTER COLUMN expires_at DROP DEFAULT;
ALTER TABLE sessions ALTER COLUMN idle_timeout DROP DEFAULT, ALTER COLUMN max_lifetime DROP DEFAULT;
COMMENT ON COLUMN sessions.idle_timeout IS NULL;
COMMENT ON COLUMN sessions.max_lifetime IS NULL;

-- +goose Down

ALTER TABLE sessions ALTER COLUMN idle_timeout SET DEFAULT '30 days', ALTER COLUMN max_lifetime SET DEFAULT '90 days';
COMMENT ON COLUMN sessions.idle_timeout IS
    'The default is a browser Session''s, only for direct INSERTs (tests); oidcstore.SessionDefaults decides.';
COMMENT ON COLUMN sessions.max_lifetime IS
    'The default is a browser Session''s, only for direct INSERTs (tests); oidcstore.SessionDefaults decides.';
ALTER TABLE provider_logins ALTER COLUMN expires_at SET DEFAULT now() + interval '10 minutes';
