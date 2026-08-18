-- +goose Up
-- +goose StatementBegin
-- Join tokens are bearer credentials, so only their SHA-256 hash is stored: a
-- database dump must not be enough to join a cluster. Tokens are single-use
-- (used_at is set on redemption) and time-limited (expires_at). Timestamps are
-- Unix seconds so comparisons need no date parsing or timezone handling.
CREATE TABLE IF NOT EXISTS cluster_join_tokens
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT    NOT NULL UNIQUE,
    role       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
-- +goose StatementEnd

-- +goose StatementBegin
-- dqlite identifies members by a raw numeric node ID and an address; neither is
-- meaningful to an operator. This table is what lets `notary cluster status`
-- show the name the operator assigned when the member joined.
--
-- node_id is TEXT because dqlite node IDs are uint64 and would overflow
-- SQLite's signed 64-bit INTEGER.
CREATE TABLE IF NOT EXISTS cluster_members
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id   TEXT    NOT NULL UNIQUE,
    name      TEXT    NOT NULL UNIQUE,
    address   TEXT    NOT NULL UNIQUE,
    joined_at INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cluster_members;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS cluster_join_tokens;
-- +goose StatementEnd
