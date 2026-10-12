-- +goose Up

-- 密码登录开关从三档砍成两档 (ADR 0017): 关闭 / 开启, 默认开启.
-- 「仅管理员」判断的是调用者有没有 Management API Role, 而那个 Role 的含义
-- 是"能不能调管理接口", 和"能不能用密码登录"是两件事.
--
-- 存量折成 'on' 而不是 'off': 密码从不随注册发放, 普通用户没有密码可用,
-- 所以全新实例上 'on' 的效果等同原来的 'admins'; 而 'off' 会让"只有
-- 用户名 + 密码"的现存所有者在升级那一刻被挡在门外.
ALTER TABLE settings DROP CONSTRAINT settings_password_login_check;
UPDATE settings SET password_login = 'on' WHERE password_login = 'admins';
ALTER TABLE settings
    ADD CONSTRAINT settings_password_login_check CHECK (password_login IN ('off', 'on')),
    ALTER COLUMN password_login SET DEFAULT 'on';
