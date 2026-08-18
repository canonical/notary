-- +goose Up
-- +goose StatementBegin
-- Certificate serial numbers get a dedicated column so uniqueness is enforced by
-- the database instead of being an implicit property of the generator.
-- SQLite cannot add a UNIQUE column with ALTER TABLE, so the constraint is applied
-- as a partial unique index. Rows that predate this migration carry '' and are
-- excluded from the index; every row written from now on carries a real serial.
ALTER TABLE certificates ADD COLUMN serial_number TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_serial_number
ON certificates(serial_number)
WHERE serial_number != '';

-- OIDC identity is only unique within an issuer, so multiple providers can be
-- configured simultaneously without one provider's `sub` colliding with another's.
ALTER TABLE users ADD COLUMN oidc_issuer TEXT;
DROP INDEX IF EXISTS idx_users_oidc_subject;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_issuer_subject
ON users(oidc_issuer, oidc_subject)
WHERE oidc_subject IS NOT NULL;
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_users_oidc_issuer_subject;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_subject
ON users(oidc_subject)
WHERE oidc_subject IS NOT NULL;
ALTER TABLE users DROP COLUMN oidc_issuer;

DROP INDEX IF EXISTS idx_certificates_serial_number;
ALTER TABLE certificates DROP COLUMN serial_number;
-- +goose StatementEnd
