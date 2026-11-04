-- +goose Up

-- 品牌 (ADR 0028): a name, the key of a Logo's blob, and a primary colour
-- as #rrggbb. The instance's are its default, empty for none; an
-- Application's NULL follows the instance's, item by item. The built-in and
-- M2M Applications always follow.
ALTER TABLE settings
    ADD COLUMN brand_name text NOT NULL DEFAULT '',
    ADD COLUMN brand_logo text NOT NULL DEFAULT '',
    ADD COLUMN brand_color text NOT NULL DEFAULT '' CHECK (brand_color = '' OR brand_color ~ '^#[0-9a-f]{6}$');

ALTER TABLE applications
    ADD COLUMN brand_name text,
    ADD COLUMN brand_logo text,
    ADD COLUMN brand_color text CHECK (brand_color ~ '^#[0-9a-f]{6}$'),
    ADD CONSTRAINT applications_brand_check CHECK (
        (brand_name IS NULL AND brand_logo IS NULL AND brand_color IS NULL) OR (NOT builtin AND type <> 'm2m'));

-- +goose Down
ALTER TABLE applications DROP CONSTRAINT applications_brand_check,
    DROP COLUMN brand_color, DROP COLUMN brand_logo, DROP COLUMN brand_name;
ALTER TABLE settings DROP COLUMN brand_color, DROP COLUMN brand_logo, DROP COLUMN brand_name;
