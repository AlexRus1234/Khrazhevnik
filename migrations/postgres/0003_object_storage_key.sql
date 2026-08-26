-- +goose Up
ALTER TABLE object_index ADD COLUMN storage_key TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE object_index DROP COLUMN storage_key;
