-- name: BeginTOTP :execrows
-- A new TOTP for the User to confirm, replacing one not yet confirmed; none
-- while one is confirmed.
INSERT INTO totp_credentials (user_id, secret) VALUES (@user_id, @secret)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, last_step = 0
WHERE totp_credentials.confirmed_at IS NULL;

-- name: TOTP :one
SELECT secret, confirmed_at, last_step FROM totp_credentials WHERE user_id = $1;

-- name: AcceptTOTPStep :execrows
-- Accepts a code for step: once, and never after a later one.
UPDATE totp_credentials SET last_step = @step WHERE user_id = @user_id AND last_step < @step;

-- name: ConfirmTOTP :execrows
-- Confirms the TOTP with the step of the code that confirmed it, if the TOTP
-- is still the one the code was checked against (ADR 0030): no row when it
-- was confirmed, begun again or used meanwhile.
UPDATE totp_credentials SET confirmed_at = now(), last_step = @step
WHERE user_id = @user_id AND confirmed_at IS NULL AND secret = @secret AND last_step < @step;

-- name: TwoFactorOn :one
-- When sub turned 两步验证 on; no row while it is off.
SELECT enabled_at FROM two_factor WHERE user_id = $1;

-- name: EnableTwoFactor :exec
-- Turns 两步验证 on; a no-op while it is.
INSERT INTO two_factor (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING;

-- name: KeepTwoFactorOn :execrows
-- Holds 两步验证 on for the rest of the transaction: a no-op write that
-- finds it on, so a concurrent DisableTwoFactor waits for this one. No row:
-- off.
UPDATE two_factor SET enabled_at = enabled_at WHERE user_id = $1;

-- name: DisableTwoFactor :execrows
-- Turns 两步验证 off; no row when it is not on.
DELETE FROM two_factor WHERE user_id = $1;

-- name: DeleteTOTP :exec
DELETE FROM totp_credentials WHERE user_id = $1;

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = $1;

-- name: AddRecoveryCodes :exec
INSERT INTO recovery_codes (user_id, mac) SELECT @user_id, unnest(@macs::bytea[]);

-- name: UnusedRecoveryCodes :many
-- The User's recovery codes not yet used, while 两步验证 is on.
SELECT c.mac FROM recovery_codes c
JOIN two_factor t ON t.user_id = c.user_id
WHERE c.user_id = $1 AND c.used_at IS NULL;

-- name: UseRecoveryCode :execrows
-- Uses up a recovery code. Audited.
WITH used AS (
    UPDATE recovery_codes SET used_at = now() WHERE user_id = @user_id AND mac = @mac AND used_at IS NULL
    RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail) SELECT 'recovery_code.used', used.user_id, '{}'::jsonb FROM used;
