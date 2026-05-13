-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS auto_sign_policies
(
    policy_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_authority_id  INTEGER NOT NULL UNIQUE,
    enabled                   INTEGER DEFAULT 1,
    certificate_validity_days INTEGER DEFAULT 90,
    certificate_limit         INTEGER DEFAULT 0,
    FOREIGN KEY (certificate_authority_id)
        REFERENCES certificate_authorities(certificate_authority_id)
        ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auto_sign_policies;
-- +goose StatementEnd