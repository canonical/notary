-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS acme_accounts
(
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT NOT NULL,
    directory_url     TEXT NOT NULL,
    private_key       TEXT NOT NULL,
    registration_uri  TEXT NOT NULL,
    registration_body TEXT NOT NULL,
    UNIQUE(email, directory_url)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS acme_servers
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    directory_url   TEXT NOT NULL,
    email           TEXT NOT NULL,
    dns_provider    TEXT NOT NULL,
    env_vars        TEXT NOT NULL DEFAULT '{}',
    active          INTEGER NOT NULL DEFAULT 0,
    acme_account_id INTEGER REFERENCES acme_accounts(id) ON DELETE SET NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS acme_servers;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS acme_accounts;
-- +goose StatementEnd
