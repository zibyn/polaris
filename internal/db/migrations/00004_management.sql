-- +goose Up

CREATE TABLE permissions (
    api     text NOT NULL REFERENCES apis (identifier) ON DELETE CASCADE,
    key     text NOT NULL,
    name    text NOT NULL,
    builtin boolean NOT NULL DEFAULT false,
    PRIMARY KEY (api, key)
);

CREATE TABLE role_permissions (
    api        text NOT NULL,
    role       text NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (api, role, permission),
    FOREIGN KEY (api, role) REFERENCES roles (api, key) ON DELETE CASCADE,
    FOREIGN KEY (api, permission) REFERENCES permissions (api, key) ON DELETE CASCADE
);

-- docs/spec/rbac.md#内置-permission-与-role
INSERT INTO permissions (api, key, name, builtin)
SELECT 'urn:polaris:management-api', key, name, true FROM (VALUES
    ('users:read', '查看 User'),
    ('users:write', '管理 User'),
    ('roles:assign', '分配业务 API 的 Role'),
    ('admin-roles:assign', '分配 Management API 的 Role'),
    ('applications:read', '查看 Application 与 API'),
    ('applications:write', '管理 Application 与 API'),
    ('config:read', '查看配置'),
    ('config:write', '修改配置'),
    ('keys:rotate', '轮换签名密钥'),
    ('audit:read', '查看审计日志')
) AS p (key, name);

INSERT INTO role_permissions (api, role, permission)
SELECT 'urn:polaris:management-api', role, permission FROM (VALUES
    ('owner', 'users:read'), ('owner', 'users:write'), ('owner', 'roles:assign'),
    ('owner', 'admin-roles:assign'), ('owner', 'applications:read'), ('owner', 'applications:write'),
    ('owner', 'config:read'), ('owner', 'config:write'), ('owner', 'keys:rotate'), ('owner', 'audit:read'),
    ('admin', 'users:read'), ('admin', 'users:write'), ('admin', 'roles:assign'),
    ('admin', 'applications:read'), ('admin', 'applications:write'),
    ('admin', 'config:read'), ('admin', 'config:write'), ('admin', 'audit:read'),
    ('readonly', 'users:read'), ('readonly', 'applications:read'), ('readonly', 'config:read'), ('readonly', 'audit:read')
) AS rp (role, permission);
