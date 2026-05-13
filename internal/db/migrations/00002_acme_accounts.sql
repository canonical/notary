-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS acme_accounts
(
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    email             TEXT NOT NULL,
    private_key       TEXT NOT NULL,
    registration_uri  TEXT NOT NULL,
    registration_body TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS acme_accounts;
-- +goose StatementEnd
