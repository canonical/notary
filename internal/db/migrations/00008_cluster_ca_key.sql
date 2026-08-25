-- +goose Up
-- +goose StatementBegin
-- The cluster CA private key, encrypted with the database encryption key.
--
-- It lives here rather than on each node's disk so that a member acquires it by
-- being admitted and replicating, not by asking for it. The join endpoint is
-- authenticated only by a single-use token, so anything it hands back is
-- available to whoever holds a stolen token; the CA key must not be.
CREATE TABLE IF NOT EXISTS cluster_ca_key
(
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    encrypted_key TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cluster_ca_key;
-- +goose StatementEnd
