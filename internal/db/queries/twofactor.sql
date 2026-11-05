-- name: BeginTOTP :execrows
-- A new TOTP for the User to confirm, replacing one not yet confirmed; none
-- while 两步验证 is on.
INSERT INTO totp_credentials (user_id, secret) VALUES (@user_id, @secret)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, last_step = 0
WHERE totp_credentials.confirmed_at IS NULL;

-- name: TOTP :one
SELECT secret, confirmed_at, last_step FROM totp_credentials WHERE user_id = $1;

-- name: AcceptTOTPStep :execrows
-- Accepts a code for step: once, and never after a later one.
UPDATE totp_credentials SET last_step = @step WHERE user_id = @user_id AND last_step < @step;

-- name: ConfirmTOTP :execrows
-- Turns 两步验证 on with the step of the code that confirmed it, if the TOTP
-- is still the one the code was checked against (ADR 0030): no row when it
-- was confirmed, begun again or used meanwhile.
UPDATE totp_credentials SET confirmed_at = now(), last_step = @step
WHERE user_id = @user_id AND confirmed_at IS NULL AND secret = @secret AND last_step < @step;

-- name: KeepTOTPOn :execrows
-- Holds 两步验证 on for the rest of the transaction: a no-op write that
-- finds it on, so a concurrent DeleteTOTP waits for this one. No row: off.
UPDATE totp_credentials SET last_step = last_step WHERE user_id = $1 AND confirmed_at IS NOT NULL;

-- name: DeleteTOTP :execrows
-- Turns 两步验证 off; no row when it is not on.
DELETE FROM totp_credentials WHERE user_id = $1 AND confirmed_at IS NOT NULL;

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = $1;

-- name: AddRecoveryCodes :exec
INSERT INTO recovery_codes (user_id, mac) SELECT @user_id, unnest(@macs::bytea[]);

-- name: UnusedRecoveryCodes :many
-- The User's recovery codes not yet used, while 两步验证 is on.
SELECT c.mac FROM recovery_codes c
JOIN totp_credentials t ON t.user_id = c.user_id AND t.confirmed_at IS NOT NULL
WHERE c.user_id = $1 AND c.used_at IS NULL;

-- name: UseRecoveryCode :execrows
-- Uses up a recovery code. Audited.
WITH used AS (
    UPDATE recovery_codes SET used_at = now() WHERE user_id = @user_id AND mac = @mac AND used_at IS NULL
    RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail) SELECT 'recovery_code.used', used.user_id, '{}'::jsonb FROM used;
