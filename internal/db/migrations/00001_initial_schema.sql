-- +goose Up
CREATE TABLE IF NOT EXISTS certificate_requests
(
    csr_id          INTEGER PRIMARY KEY AUTOINCREMENT,
	csr             TEXT NOT NULL UNIQUE,
	status          TEXT DEFAULT 'Outstanding',
	certificate_id  INTEGER,
	user_email      TEXT,
	CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active')),
	CHECK (NOT (certificate_id == NULL AND status == 'Active' )),
	CHECK (NOT (certificate_id != NULL AND status == 'Outstanding')),
    CHECK (NOT (certificate_id != NULL AND status == 'Rejected')),
    CHECK (NOT (certificate_id != NULL AND status == 'Revoked'))
);
CREATE TABLE IF NOT EXISTS certificates
(
    certificate_id  INTEGER PRIMARY KEY AUTOINCREMENT,
	certificate     TEXT NOT NULL UNIQUE,
	issuer_id       INTEGER
);
CREATE TABLE IF NOT EXISTS certificate_authorities
(
    certificate_authority_id INTEGER PRIMARY KEY AUTOINCREMENT,
	crl                      TEXT,
	enabled                  INTEGER DEFAULT 0,
	private_key_id           INTEGER,
	certificate_id           INTEGER,
	csr_id                   INTEGER NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS private_keys
(
    private_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
	private_key    TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS users
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
	oidc_subject    TEXT,
	email           TEXT,
	hashed_password TEXT,
	role_id         INTEGER NOT NULL,
	CHECK (role_id IN (0, 1, 2, 3)),
	CHECK (
		(email IS NOT NULL AND trim(email) != '') OR
		(oidc_subject IS NOT NULL AND trim(oidc_subject) != '')
	)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
ON users(email)
WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_subject
ON users(oidc_subject)
WHERE oidc_subject IS NOT NULL;
CREATE TABLE IF NOT EXISTS encryption_keys
(
    encryption_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
	encryption_key    TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS jwt_secret
(
	id               INTEGER PRIMARY KEY CHECK (id = 1),
	encrypted_secret TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS jwt_secret;
DROP TABLE IF EXISTS encryption_keys;
DROP INDEX IF EXISTS idx_users_oidc_subject;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS private_keys;
DROP TABLE IF EXISTS certificate_authorities;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS certificate_requests;
