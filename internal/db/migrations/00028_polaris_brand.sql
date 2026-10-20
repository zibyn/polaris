-- +goose Up

-- The built-in Applications display the product name; it changed to Polaris.
UPDATE applications SET name = 'Polaris 管理端' WHERE client_id = 'stars-auth-console';
UPDATE applications SET name = 'Polaris 账号中心' WHERE client_id = 'stars-auth-account';

-- +goose Down

UPDATE applications SET name = 'Stars Auth 管理端' WHERE client_id = 'stars-auth-console';
UPDATE applications SET name = 'Stars Auth 账号中心' WHERE client_id = 'stars-auth-account';
