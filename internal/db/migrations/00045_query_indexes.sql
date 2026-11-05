-- +goose Up

-- ListAudit finds the events a User did (detail.by), newest first.
CREATE INDEX audit_log_by_id_idx ON audit_log ((detail ->> 'by'), id);
-- Counting and deleting a Role's holders; the primary key leads with user_id.
CREATE INDEX user_roles_api_role_idx ON user_roles (api, role);

-- +goose Down

DROP INDEX user_roles_api_role_idx;
DROP INDEX audit_log_by_id_idx;
