-- +goose Up
-- +goose StatementBegin
CREATE TABLE certificate_requests
(
    csr_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    csr             TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'Outstanding',
    certificate_id  INTEGER,
    user_email      TEXT,

    CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active', 'Failed')),
    CHECK ((status = 'Active') = (certificate_id IS NOT NULL))
);

CREATE TABLE certificates
(
    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate    TEXT NOT NULL UNIQUE,
    issuer_id      INTEGER NOT NULL DEFAULT 0,
    serial_number  TEXT NOT NULL
);

CREATE TABLE certificate_authorities
(
    certificate_authority_id INTEGER PRIMARY KEY AUTOINCREMENT,
    crl                      TEXT,
    enabled                  INTEGER NOT NULL DEFAULT 0,
    private_key_id           INTEGER,
    certificate_id           INTEGER,
    csr_id                   INTEGER NOT NULL UNIQUE
);

CREATE TABLE private_keys
(
    private_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
    private_key    TEXT NOT NULL UNIQUE
);

CREATE TABLE users
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    oidc_issuer     TEXT,
    oidc_subject    TEXT,
    email           TEXT,
    hashed_password TEXT,
    role_id         INTEGER NOT NULL,

    CHECK (role_id IN (0, 1, 2, 3)),
    CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL)),
    CHECK (email IS NOT NULL OR oidc_subject IS NOT NULL)
);

CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX idx_users_oidc_identity
ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE encryption_keys
(
    encryption_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
    encryption_key    TEXT NOT NULL UNIQUE
);

CREATE TABLE jwt_secret
(
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    encrypted_secret TEXT NOT NULL
);

CREATE TABLE acme_accounts
(
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT NOT NULL,
    directory_url     TEXT NOT NULL,
    private_key       TEXT NOT NULL,
    registration_uri  TEXT NOT NULL,
    registration_body TEXT NOT NULL,
    UNIQUE (email, directory_url)
);

CREATE TABLE acme_servers
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

CREATE TABLE cluster_join_tokens
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE cluster_members
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id   TEXT NOT NULL UNIQUE,
    name      TEXT NOT NULL UNIQUE,
    address   TEXT NOT NULL UNIQUE,
    joined_at INTEGER NOT NULL,
    heartbeat INTEGER,
    sealed    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE acme_issuance_attempts
(
    csr_id     INTEGER PRIMARY KEY REFERENCES certificate_requests(csr_id) ON DELETE CASCADE,
    node_id    TEXT NOT NULL,
    started_at INTEGER NOT NULL
);

CREATE TABLE cluster_ca_key
(
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    encrypted_key TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE cluster_ca_key;
DROP TABLE acme_issuance_attempts;
DROP TABLE cluster_members;
DROP TABLE cluster_join_tokens;
DROP TABLE acme_servers;
DROP TABLE acme_accounts;
DROP TABLE jwt_secret;
DROP TABLE encryption_keys;
DROP TABLE users;
DROP TABLE private_keys;
DROP TABLE certificate_authorities;
DROP TABLE certificates;
DROP TABLE certificate_requests;
-- +goose StatementEnd
