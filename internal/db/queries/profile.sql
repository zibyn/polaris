-- name: UserProfile :one
SELECT COALESCE(nickname, '')::text AS nickname, COALESCE(avatar, '')::text AS avatar FROM users WHERE id = $1;

-- name: LockUserProfile :one
-- The User's avatar key, with the row locked for the change that replaces it.
SELECT COALESCE(avatar, '')::text AS avatar FROM users WHERE id = $1 FOR UPDATE;

-- name: SetNickname :execrows
UPDATE users SET nickname = NULLIF(@nickname::text, '') WHERE id = @user_id;

-- name: SetAvatar :execrows
UPDATE users SET avatar = NULLIF(@avatar::text, '') WHERE id = @user_id;
