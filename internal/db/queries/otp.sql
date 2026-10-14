-- name: LockSends :exec
-- Serialises sends so two requests cannot both pass a limit.
-- ponytail: one global lock; per-Identifier locks if sends get busy.
SELECT pg_advisory_xact_lock(hashtext('sends'));

-- name: SendCounts :one
SELECT count(*) FILTER (WHERE identifier = @identifier AND sent_at > @minute_ago) AS identifier_minute,
       count(*) FILTER (WHERE identifier = @identifier AND sent_at > @hour_ago) AS identifier_hour,
       count(*) FILTER (WHERE identifier = @identifier) AS identifier_day,
       count(*) FILTER (WHERE ip = @ip AND sent_at > @hour_ago) AS ip_hour,
       count(*) AS instance_day,
       (SELECT daily_send_limit FROM settings) AS daily_limit
FROM sends
WHERE sent_at > @day_ago;

-- name: RecordSend :exec
INSERT INTO sends (identifier, ip, sent_at) VALUES ($1, $2, $3);

-- name: RecordInviteSend :exec
-- 注册邀请写一条 identifier 与 ip 都为空的记录: 它计入 SendCounts 的
-- instance_day (实例每日发送上限), 而按标识符、按 IP 的计数永远匹配不上
-- 它 —— 真实的标识符与 clientIP 都不为空, 邀请也不该占它们那两份额度。
INSERT INTO sends (identifier, ip, sent_at) VALUES ('', '', $1);

-- name: PutCode :exec
INSERT INTO codes (identifier, code, expires_at) VALUES ($1, $2, $3)
ON CONFLICT (identifier) DO UPDATE SET code = EXCLUDED.code, attempts = 0, expires_at = EXCLUDED.expires_at;

-- name: TryCode :one
-- Counts a try before the code is compared, so parallel guesses still get
-- five in all.
UPDATE codes SET attempts = attempts + 1
WHERE identifier = @identifier AND attempts < 5 AND expires_at > @now
RETURNING code;

-- name: DeleteCode :execrows
DELETE FROM codes WHERE identifier = $1 AND code = $2;

-- name: DeleteExpiredOTP :exec
WITH c AS (DELETE FROM codes WHERE codes.expires_at < now())
DELETE FROM sends WHERE sends.sent_at < now() - interval '1 day';
