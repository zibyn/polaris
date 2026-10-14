-- 注册邀请: 管理员发出的一条一次性链接, 本人点开设置自己的密码 (ADR 0016).
-- 表里只有 token 的 SHA-256, 明文只出现在那封邮件里。

-- name: PutInvite :exec
-- 重发就是替换: invites 上 user_id 唯一, 所以旧 token 立刻失效。
-- 7 天有效, 用数据库的钟算, 和 LiveInvite / AcceptInvite 的是同一个。
INSERT INTO invites (token_hash, user_id, expires_at)
VALUES (@token_hash, @user_id, now() + interval '7 days')
ON CONFLICT (user_id) DO UPDATE
SET token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at, created_at = now();

-- name: LiveInvite :one
-- 还能用的邀请: 没用过 (用过就删了)、没被撤销 (撤销也是删)、没过期。
SELECT user_id FROM invites WHERE token_hash = $1 AND expires_at > now();

-- name: DeleteInvite :exec
-- 发信失败时把刚铸出来的 token 丢掉, 不留一条可用链接。
DELETE FROM invites WHERE user_id = $1;

-- name: RevokeInvite :execrows
-- 撤销, 审计的操作人是管理员。撤销一条本来就没有的邀请不算一次撤销。
WITH gone AS (
    DELETE FROM invites WHERE user_id = @user_id RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'invite.revoked', gone.user_id, jsonb_build_object('by', @by::text) FROM gone;

-- name: AcceptInvite :one
-- 接受: 花掉这条邀请、把密码写成本人自己的、待激活的随即激活, 审计的操作人
-- 是本人。三件事和删除在同一句里, 所以一条链接只能兑现一次 —— 并发里只有
-- 一个请求删得到那一行。
-- 被禁用的账号不接受邀请: 链接不花掉, 也不写密码, 报告成失效让本人去找管理员。
WITH spent AS (
    DELETE FROM invites
    WHERE token_hash = @token_hash AND expires_at > now()
      AND user_id IN (SELECT id FROM users WHERE disabled_at IS NULL)
    RETURNING user_id
), activated AS (
    UPDATE users SET status = 'active' WHERE users.id IN (SELECT user_id FROM spent) RETURNING users.id
), put AS (
    INSERT INTO passwords (user_id, hash) SELECT spent.user_id, @hash::text FROM spent
    ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash
    RETURNING user_id
)
INSERT INTO audit_log (event, sub, detail)
SELECT 'invite.accepted', put.user_id, jsonb_build_object('by', put.user_id) FROM put
RETURNING sub;

-- name: DeleteExpiredInvites :exec
DELETE FROM invites WHERE expires_at < now();
