-- +goose Up

-- Management API writes audit themselves now, named 名词.动词 instead of by
-- their operation ID (ADR 0025); the history takes the new names too.
UPDATE audit_log SET event = n.new
FROM (VALUES
    ('create-application', 'application.created'),
    ('update-application', 'application.updated'),
    ('delete-application', 'application.deleted'),
    ('new-application-secret', 'application.secret_regenerated'),
    ('set-application-auth-method', 'application.auth_method_changed'),
    ('put-api', 'api.saved'),
    ('put-permission', 'permission.saved'),
    ('put-role', 'role.saved'),
    ('put-channel', 'channel.saved'),
    ('delete-api', 'api.deleted'),
    ('delete-permission', 'permission.deleted'),
    ('delete-role', 'role.deleted'),
    ('delete-channel', 'channel.deleted'),
    ('delete-provider', 'provider.deleted'),
    ('create-provider', 'provider.created'),
    ('update-provider', 'provider.updated'),
    ('enable-provider', 'provider.enabled'),
    ('disable-provider', 'provider.disabled'),
    ('test-channel', 'channel.tested')
) AS n (old, new)
WHERE audit_log.event = n.old;

-- +goose Down

UPDATE audit_log SET event = n.old
FROM (VALUES
    ('create-application', 'application.created'),
    ('update-application', 'application.updated'),
    ('delete-application', 'application.deleted'),
    ('new-application-secret', 'application.secret_regenerated'),
    ('set-application-auth-method', 'application.auth_method_changed'),
    ('put-api', 'api.saved'),
    ('put-permission', 'permission.saved'),
    ('put-role', 'role.saved'),
    ('put-channel', 'channel.saved'),
    ('delete-api', 'api.deleted'),
    ('delete-permission', 'permission.deleted'),
    ('delete-role', 'role.deleted'),
    ('delete-channel', 'channel.deleted'),
    ('delete-provider', 'provider.deleted'),
    ('create-provider', 'provider.created'),
    ('update-provider', 'provider.updated'),
    ('enable-provider', 'provider.enabled'),
    ('disable-provider', 'provider.disabled'),
    ('test-channel', 'channel.tested')
) AS n (old, new)
WHERE audit_log.event = n.new;
