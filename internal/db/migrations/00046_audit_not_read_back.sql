-- +goose Up

-- Business state no longer read back out of audit_log, which keeps its
-- retention and nothing else: when the User spent their 注册邀请 (cleared
-- by the next invite sent), and when the instance last audited hitting its
-- daily send limit (once a day).
ALTER TABLE users ADD COLUMN invite_accepted_at timestamptz;
UPDATE users u SET invite_accepted_at = l.at
FROM (SELECT DISTINCT ON (sub) sub, event, at FROM audit_log
      WHERE event IN ('invite.sent', 'invite.accepted', 'invite.revoked')
      ORDER BY sub, at DESC, id DESC) l
WHERE l.sub = u.id AND l.event = 'invite.accepted';

ALTER TABLE settings ADD COLUMN daily_cap_audited_at timestamptz;
UPDATE settings SET daily_cap_audited_at = (SELECT max(at) FROM audit_log WHERE event = 'send.daily_cap_reached');

-- Whoever writes an event knows who did it: detail.byType is written with
-- detail.by (internal/audit), not looked up in users and applications.
DROP TRIGGER audit_by_type ON audit_log;
DROP FUNCTION audit_by_type();

-- +goose Down

-- +goose StatementBegin
CREATE FUNCTION audit_by_type() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.detail ->> 'by' IS NOT NULL AND NEW.detail ->> 'byType' IS NULL THEN
        NEW.detail := NEW.detail || jsonb_build_object('byType',
            CASE WHEN EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.detail ->> 'by') THEN 'user'
                 WHEN EXISTS (SELECT 1 FROM applications a WHERE a.client_id = NEW.detail ->> 'by') THEN 'application'
            END);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_by_type BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_by_type();

ALTER TABLE settings DROP COLUMN daily_cap_audited_at;
ALTER TABLE users DROP COLUMN invite_accepted_at;
