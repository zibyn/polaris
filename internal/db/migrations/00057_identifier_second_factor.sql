-- +goose Up

-- The User added this phone number or email as a 两步验证 second factor
-- (ADR 0038). On the Identifier's row, so it goes with the row when the
-- Identifier is removed and stays when its value is replaced.
ALTER TABLE identifiers ADD COLUMN second_factor boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE identifiers DROP COLUMN second_factor;
