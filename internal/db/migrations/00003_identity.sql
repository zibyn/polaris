-- +goose Up

-- id is the sub: random, opaque, never reused.
CREATE TABLE users (
    id         text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Values are normalised before they get here (lowercase email and username,
-- E.164 phone). Usernames hold no '@' or '+', so a value names one Identifier
-- whatever its kind.
CREATE TABLE identifiers (
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind    text NOT NULL CHECK (kind IN ('phone', 'email', 'username')),
    value   text NOT NULL,
    PRIMARY KEY (kind, value),
    UNIQUE (user_id, kind)
);
CREATE UNIQUE INDEX ON identifiers (value);

-- argon2id, PHC string format.
CREATE TABLE passwords (
    user_id text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    hash    text NOT NULL
);

CREATE TABLE roles (
    api     text NOT NULL REFERENCES apis (identifier) ON DELETE CASCADE,
    key     text NOT NULL,
    name    text NOT NULL,
    builtin boolean NOT NULL DEFAULT false,
    PRIMARY KEY (api, key)
);

CREATE TABLE user_roles (
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    api     text NOT NULL,
    role    text NOT NULL,
    PRIMARY KEY (user_id, api, role),
    FOREIGN KEY (api, role) REFERENCES roles (api, key) ON DELETE CASCADE
);

INSERT INTO roles (api, key, name, builtin) VALUES
    ('urn:polaris:management-api', 'owner', '所有者', true),
    ('urn:polaris:management-api', 'admin', '管理员', true),
    ('urn:polaris:management-api', 'readonly', '只读', true);

-- Instance settings, one row.
CREATE TABLE settings (
    id             boolean PRIMARY KEY DEFAULT true CHECK (id),
    password_login text NOT NULL DEFAULT 'admins' CHECK (password_login IN ('off', 'admins', 'all')),
    -- One-time setup token, sealed with the master key so every replica and
    -- restart prints the same one.
    setup_token    bytea,
    -- Set when the first owner is created; the setup page never reopens.
    setup_done     boolean NOT NULL DEFAULT false
);
INSERT INTO settings DEFAULT VALUES;

-- Browser Sessions, keyed by the SHA-256 of the cookie value. Idle ones are
-- dead and deleted by the hourly cleanup.
CREATE TABLE sessions (
    id_hash      bytea PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    auth_time    timestamptz NOT NULL,
    amr          text[] NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON sessions (user_id);
CREATE INDEX ON sessions (last_seen_at);
