-- +goose Up
CREATE TABLE certificate_requests_new
(
    csr_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    csr             TEXT NOT NULL UNIQUE,
    status          TEXT DEFAULT 'Outstanding',
    certificate_id  INTEGER,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active')),
    CHECK (NOT (certificate_id == NULL AND status == 'Active' )),
    CHECK (NOT (certificate_id != NULL AND status == 'Outstanding')),
    CHECK (NOT (certificate_id != NULL AND status == 'Rejected')),
    CHECK (NOT (certificate_id != NULL AND status == 'Revoked'))
);
INSERT INTO certificate_requests_new (csr_id, csr, status, certificate_id, user_id)
SELECT
    csr.csr_id,
    csr.csr,
    csr.status,
    csr.certificate_id,
    u.id
FROM certificate_requests csr
LEFT JOIN users u ON u.email IS NOT NULL AND trim(u.email) != '' AND u.email = csr.user_email;
DROP TABLE certificate_requests;
ALTER TABLE certificate_requests_new RENAME TO certificate_requests;
DROP INDEX IF EXISTS idx_users_email;
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL AND trim(email) != '';

-- +goose Down
DROP INDEX IF EXISTS idx_users_email;
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE certificate_requests_old
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
INSERT INTO certificate_requests_old (csr_id, csr, status, certificate_id, user_email)
SELECT
    csr.csr_id,
    csr.csr,
    csr.status,
    csr.certificate_id,
    u.email
FROM certificate_requests csr
LEFT JOIN users u ON u.id = csr.user_id;
DROP TABLE certificate_requests;
ALTER TABLE certificate_requests_old RENAME TO certificate_requests;
