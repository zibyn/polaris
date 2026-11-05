-- name: UserProfile :one
SELECT COALESCE(nickname, '')::text AS nickname, COALESCE(avatar, '')::text AS avatar, profile, profile_updated_at
FROM users WHERE id = $1;

-- name: UserAvatar :one
-- The User's avatar key, for the change that replaces it (SetAvatar).
SELECT COALESCE(avatar, '')::text AS avatar FROM users WHERE id = $1;

-- name: SetProfile :execrows
-- Sets the nickname when set_nickname, merges set into the profile claims
-- and drops the keys in clear. Stamps profile_updated_at and queues
-- user.updated (changed: profile) only when something changes; both read
-- the row as it was before the update.
WITH put AS (
    UPDATE users SET
        nickname = CASE WHEN @set_nickname::boolean THEN NULLIF(@nickname::text, '') ELSE users.nickname END,
        profile = (users.profile || @set::jsonb) - @clear::text[],
        profile_updated_at = CASE
            WHEN (@set_nickname::boolean AND users.nickname IS DISTINCT FROM NULLIF(@nickname::text, ''))
              OR users.profile <> (users.profile || @set::jsonb) - @clear::text[] THEN now()
            ELSE users.profile_updated_at END
    WHERE users.id = @user_id RETURNING users.id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', u.id, 'changed', '{profile}'::text[])
    FROM users u JOIN applications a ON a.webhook_url IS NOT NULL
    WHERE u.id = @user_id AND (
        (@set_nickname::boolean AND u.nickname IS DISTINCT FROM NULLIF(@nickname::text, ''))
        OR u.profile <> (u.profile || @set::jsonb) - @clear::text[])
)
SELECT 1 FROM put;

-- name: SetAvatar :execrows
-- Queues user.updated (changed: profile) when the avatar changes. No row
-- when the avatar is no longer old, the one read (ADR 0030): replaced
-- meanwhile, whose blob the caller would otherwise leave behind.
WITH put AS (
    UPDATE users SET avatar = NULLIF(@avatar::text, ''),
        profile_updated_at = CASE WHEN users.avatar IS DISTINCT FROM NULLIF(@avatar::text, '') THEN now() ELSE users.profile_updated_at END
    WHERE users.id = @user_id AND COALESCE(users.avatar, '') = @old::text RETURNING users.id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT a.client_id, jsonb_build_object('type', 'user.updated', 'sub', u.id, 'changed', '{profile}'::text[])
    FROM put, users u JOIN applications a ON a.webhook_url IS NOT NULL
    WHERE u.id = put.id AND u.avatar IS DISTINCT FROM NULLIF(@avatar::text, '')
)
SELECT 1 FROM put;
