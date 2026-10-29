-- name: LockedOut :one
SELECT EXISTS (SELECT 1 FROM lockouts WHERE key = $1 AND until > now());

-- name: LoginFailed :one
-- Records a failure of key and returns its failures within the window,
-- this one included.
WITH f AS (INSERT INTO login_failures (key) VALUES (@key))
SELECT (count(*) + 1)::int FROM login_failures
WHERE login_failures.key = @key AND login_failures.at > now() - make_interval(secs => @window_secs::float8);

-- name: LockOut :one
-- Locks key out for a while, until the time it returns; its count starts over.
WITH cleared AS (DELETE FROM login_failures WHERE login_failures.key = @key)
INSERT INTO lockouts (key, until) VALUES (@key, now() + make_interval(secs => @lock_secs::float8))
ON CONFLICT (key) DO UPDATE SET until = EXCLUDED.until
RETURNING until;

-- name: ClearLoginFailures :exec
DELETE FROM login_failures WHERE key = $1;

-- name: DeleteOldLoginFailures :exec
WITH expired AS (DELETE FROM lockouts WHERE until < now())
DELETE FROM login_failures WHERE at < now() - interval '1 day';
