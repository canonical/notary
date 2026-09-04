-- +goose Up
CREATE TABLE IF NOT EXISTS cluster_members
(
    name    TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS cluster_join_tokens
(
    name       TEXT PRIMARY KEY,
    secret     TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS cluster_join_tokens;
DROP TABLE IF EXISTS cluster_members;
