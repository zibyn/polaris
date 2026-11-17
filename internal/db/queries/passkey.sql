-- name: PasskeyLogin :one
-- Whether the instance offers Passkey login (docs/spec/consoles.md#设置); a
-- ceremony while it is off is refused.
SELECT passkey_login FROM settings;

-- name: UserPasskeys :many
SELECT id, name, created_at, last_used_at FROM passkeys
WHERE user_id = $1 ORDER BY created_at;

-- name: PasskeyExclusions :many
-- The credential IDs a registration options must exclude: the User's
-- Passkeys, so an authenticator holding one refuses to make another.
SELECT credential_id, transports FROM passkeys WHERE user_id = $1;

-- name: PasskeyByCredentialID :one
-- The Passkey a login assertion names: its owner and the key to check the
-- signature with.
SELECT user_id, name, public_key, sign_count, backup_eligible, backup_state
FROM passkeys WHERE credential_id = $1;

-- name: SignInPasskey :exec
UPDATE passkeys SET last_used_at = now(), sign_count = $2
WHERE credential_id = $1;

-- name: AuditPasskeyCounter :exec
-- A login refused because the counter went backwards: the Passkey may have
-- been cloned. Audited as passkey.counter_regressed.
INSERT INTO audit_log (event, sub, detail)
VALUES ('passkey.counter_regressed', @sub::text, jsonb_build_object('name', @name::text, 'count', @count::int8));

-- name: AddPasskey :one
-- Audited as passkey.added. No row when the credential already exists.
WITH put AS (
    INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, aaguid,
                          backup_eligible, backup_state, transports, name)
    VALUES (@user_id, @credential_id, @public_key, @sign_count, @aaguid,
            @backup_eligible, @backup_state, @transports, @name)
    ON CONFLICT DO NOTHING
    RETURNING id, name, created_at
), audit AS (
    INSERT INTO audit_log (event, sub, detail)
    SELECT 'passkey.added', @user_id::text, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, ''), 'name', put.name) FROM put
)
SELECT id, name, created_at FROM put;

-- name: RenamePasskey :execrows
-- Audited as passkey.renamed. No row when the Passkey is not the User's.
WITH renamed AS (
    UPDATE passkeys SET name = @name WHERE passkeys.id = @id AND user_id = @user_id RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'passkey.renamed', renamed.user_id, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, ''), 'name', @name::text) FROM renamed;

-- name: LastSecondFactor :one
-- Whether the Passkey id is sub's last, and with 两步验证 on and no TOTP
-- all it has besides the recovery codes.
SELECT (EXISTS (SELECT 1 FROM two_factor t WHERE t.user_id = @sub)
   AND NOT EXISTS (SELECT 1 FROM totp_credentials c WHERE c.user_id = @sub AND c.confirmed_at IS NOT NULL)
   AND (SELECT count(*) FROM passkeys p WHERE p.user_id = @sub) = 1
   AND EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = @sub AND p.id = @id::text))::boolean AS last;

-- name: DeletePasskey :execrows
-- Audited as passkey.removed. No row when the Passkey is not the User's.
WITH gone AS (
    DELETE FROM passkeys WHERE passkeys.id = @id AND user_id = @user_id RETURNING user_id, name
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'passkey.removed', gone.user_id, jsonb_build_object('by', @by_id::text, 'byType', NULLIF(@by_type::text, ''), 'name', gone.name) FROM gone;

-- name: PutPasskeyChallenge :exec
-- A registration challenge in flight for this Session, replacing one
-- already there.
INSERT INTO passkey_challenges (session_id, user_id, challenge, expires_at)
VALUES (@session_id, @user_id, @challenge, @expires_at)
ON CONFLICT (session_id) DO UPDATE SET user_id = EXCLUDED.user_id,
    challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at;

-- name: TakePasskeyChallenge :one
-- Takes the Session's registration challenge, live or not; taken once.
DELETE FROM passkey_challenges WHERE session_id = $1
RETURNING user_id, challenge, (expires_at > now()) AS live;

-- name: DeleteExpiredPasskeyChallenges :exec
DELETE FROM passkey_challenges WHERE expires_at < now();
