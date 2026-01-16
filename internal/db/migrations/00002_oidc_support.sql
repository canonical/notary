-- +goose Up
-- +goose StatementBegin
-- This migration adds OIDC authentication support to the users table.
-- It allows users to have OIDC identities linked to their accounts and supports
-- pure OIDC users (without local passwords).

-- Create new users table with OIDC support
CREATE TABLE IF NOT EXISTS users_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT,  -- Now nullable to support OIDC-only users
    role_id         INTEGER NOT NULL,
    oidc_subject    TEXT,  -- OIDC provider's subject identifier (sub claim)
    
    CHECK (trim(email) != '')
);

-- Copy existing data from old table
INSERT INTO users_new (id, email, hashed_password, role_id)
SELECT id, email, hashed_password, role_id FROM users;

-- Drop old table
DROP TABLE users;

-- Rename new table to users
ALTER TABLE users_new RENAME TO users;

-- Create unique index on oidc_subject to prevent duplicate OIDC identities
-- Partial index only indexes non-NULL values
CREATE UNIQUE INDEX idx_users_oidc_subject 
ON users(oidc_subject) 
WHERE oidc_subject IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Rollback: Recreate original users table without OIDC support
CREATE TABLE IF NOT EXISTS users_rollback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    role_id         INTEGER NOT NULL,
    
    CHECK (trim(email) != ''),
    CHECK (trim(hashed_password) != '')
);

-- Copy data back (excluding OIDC-only users without passwords)
INSERT INTO users_rollback (id, email, hashed_password, role_id)
SELECT id, email, hashed_password, role_id 
FROM users
WHERE hashed_password IS NOT NULL;

DROP TABLE users;

ALTER TABLE users_rollback RENAME TO users;

-- +goose StatementEnd
