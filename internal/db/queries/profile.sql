-- name: UserProfile :one
SELECT COALESCE(nickname, '')::text AS nickname, COALESCE(avatar, '')::text AS avatar FROM users WHERE id = $1;

-- name: LockUserProfile :one
-- The User's avatar key, with the row locked for the change that replaces it.
SELECT COALESCE(avatar, '')::text AS avatar FROM users WHERE id = $1 FOR UPDATE;

-- name: SetNickname :execrows
-- Queues user.updated (changed: profile) when the nickname changes; the
-- hooks CTE reads the row as it was before the update.
WITH put AS (
    UPDATE users SET nickname = NULLIF(@nickname::text, '') WHERE users.id = @user_id RETURNING users.id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT e.client_id, e.payload FROM users u, user_event('user.updated', u.id, '{profile}') e
    WHERE u.id = @user_id AND u.nickname IS DISTINCT FROM NULLIF(@nickname::text, '')
)
SELECT 1 FROM put;

-- name: SetAvatar :execrows
-- Queues user.updated (changed: profile) when the avatar changes.
WITH put AS (
    UPDATE users SET avatar = NULLIF(@avatar::text, '') WHERE users.id = @user_id RETURNING users.id
), hooks AS (
    INSERT INTO webhook_deliveries (client_id, payload)
    SELECT e.client_id, e.payload FROM users u, user_event('user.updated', u.id, '{profile}') e
    WHERE u.id = @user_id AND u.avatar IS DISTINCT FROM NULLIF(@avatar::text, '')
)
SELECT 1 FROM put;
