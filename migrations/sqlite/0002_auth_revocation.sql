-- +goose Up
ALTER TABLE api_tokens ADD COLUMN revoked_at INTEGER;

-- +goose Down
ALTER TABLE api_tokens DROP COLUMN revoked_at;
