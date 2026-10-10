-- +goose Up

-- 审计的操作者 (ADR 0015): a User's sub or an M2M Application's client_id.
-- byType joins detail.by on every new row, so the console can name an
-- Application operator — and still show its client_id once the Application
-- is gone. Rows without it are Users (旧记录按 User 解析). Derived from by
-- here, not by each caller, so Go-built details and SQL ones are typed alike.
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

-- +goose Down

DROP TRIGGER audit_by_type ON audit_log;
DROP FUNCTION audit_by_type();
