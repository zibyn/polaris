-- +goose Up

-- 注册邀请 (ADR 0016): 管理员发出的一条一次性链接, 本人点开设置自己的密码。
-- 表里只有 token 的 SHA-256, 明文只出现在那封邮件里。
CREATE TABLE invites (
    token_hash bytea PRIMARY KEY,
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- 一个 User 同时只有一条邀请, 所以重发就是替换, 旧链接立刻失效。
CREATE UNIQUE INDEX ON invites (user_id);

-- ponytail: 只支持邮箱, 所以没有 invitation 的投递渠道字段。等短信邀请
-- 有了自己的模板与签名 (阿里云那套号码认证模板是验证码专用), 再谈手机号。

-- +goose Down

DROP TABLE invites;
