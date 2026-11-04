-- +goose Up

-- An Application's own login methods (ADR 0027): 'sms', 'email', 'password',
-- 'passkey' and 'provider:<id>'. NULL follows the instance; the built-in and
-- M2M Applications always do. Empty once the last Provider it named is
-- deleted: nobody can sign in to it, and the console warns.
ALTER TABLE applications ADD COLUMN login_methods text[]
    CHECK (login_methods IS NULL OR (NOT builtin AND type <> 'm2m'));

-- The login method the Session was signed in with, in the same terms.
-- 单点登录 into an Application with its own set checks it against that set.
-- NULL for a Session signed in before this column existed.
ALTER TABLE sessions ADD COLUMN login_method text;

-- +goose Down
ALTER TABLE sessions DROP COLUMN login_method;
ALTER TABLE applications DROP COLUMN login_methods;
