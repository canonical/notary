package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// schemaUpdates are applied once, in order, when the dqlite database is opened.
var schemaUpdates = []string{
	schemaInitial,
	schemaACME,
}

const schemaInitial = `
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
`

const schemaACME = `
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
`

func applySchema(ctx context.Context, sqldb *sql.DB) error {
	if _, err := sqldb.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_updates (
			id INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_updates: %w", err)
	}

	var version int
	if err := sqldb.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM schema_updates`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	for i, body := range schemaUpdates {
		id := i + 1
		if id <= version {
			continue
		}
		tx, err := sqldb.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := execStatements(ctx, tx, body); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("schema update %d: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_updates (id, applied_at) VALUES (?, ?)`,
			id, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func execStatements(ctx context.Context, tx *sql.Tx, body string) error {
	for _, stmt := range splitSQL(body) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w (statement: %s)", err, truncate(stmt, 80))
		}
	}
	return nil
}

func splitSQL(body string) []string {
	var out []string
	for _, part := range strings.Split(body, ";") {
		stmt := strings.TrimSpace(part)
		if stmt == "" {
			continue
		}
		out = append(out, stmt)
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
