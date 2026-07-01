-- +goose Up
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500);

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS avatar_url;
