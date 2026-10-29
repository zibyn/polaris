-- +goose Up

-- An Application that lets Users sign in may turn away a User without a Role
-- on its default API (docs/spec/rbac.md): no default API, nothing to check.
ALTER TABLE applications ADD COLUMN require_role boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT applications_require_role_check CHECK (NOT require_role OR (default_api IS NOT NULL AND type <> 'm2m'));

-- +goose Down

ALTER TABLE applications DROP CONSTRAINT applications_require_role_check,
    DROP COLUMN require_role;
