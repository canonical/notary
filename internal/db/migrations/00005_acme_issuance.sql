-- +goose Up
-- +goose StatementBegin
-- 'Failed' records a request whose issuance was interrupted and cannot be
-- resumed. It is terminal, like 'Rejected' and 'Revoked', and carries no
-- certificate. SQLite cannot alter a CHECK constraint in place, so the table is
-- rebuilt. No other table declares a foreign key against certificate_requests,
-- so the rebuild needs no foreign key handling (and PRAGMA foreign_keys would
-- be a no-op here anyway, since goose runs each migration in a transaction).
CREATE TABLE certificate_requests_new
(
    csr_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    csr             TEXT NOT NULL UNIQUE,
    status          TEXT DEFAULT 'Outstanding',
    certificate_id  INTEGER,
    user_email      TEXT,

    CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active', 'Failed')),
    CHECK (NOT (certificate_id == NULL AND status == 'Active' )),
    CHECK (NOT (certificate_id != NULL AND status == 'Outstanding')),
    CHECK (NOT (certificate_id != NULL AND status == 'Rejected')),
    CHECK (NOT (certificate_id != NULL AND status == 'Revoked')),
    CHECK (NOT (certificate_id != NULL AND status == 'Failed'))
);

INSERT INTO certificate_requests_new (csr_id, csr, status, certificate_id, user_email)
SELECT csr_id, csr, status, certificate_id, user_email FROM certificate_requests;

DROP TABLE certificate_requests;

ALTER TABLE certificate_requests_new RENAME TO certificate_requests;
-- +goose StatementEnd

-- +goose StatementBegin
-- ACME issuance runs outside the database: notary hands the CSR to lego, which
-- polls a DNS-01 challenge against an external CA for as long as DNS
-- propagation takes. That work lives in one process, so if the node running it
-- dies the request is orphaned, sitting at 'Outstanding' with nothing to
-- indicate that anything went wrong.
--
-- This table is the durable record that an attempt is in flight, and which node
-- owns it. A row exists only for the duration of the attempt: it is inserted
-- before handing off to lego and deleted once the attempt finishes, whether it
-- succeeded or failed. A row that outlives its owner is the signal the
-- leader-change reconciler looks for.
--
-- node_id is TEXT for the same reason as cluster_members.node_id: dqlite node
-- IDs are uint64 and would overflow SQLite's signed 64-bit INTEGER.
CREATE TABLE IF NOT EXISTS acme_issuance_attempts
(
    csr_id     INTEGER PRIMARY KEY REFERENCES certificate_requests(csr_id) ON DELETE CASCADE,
    node_id    TEXT    NOT NULL,
    started_at INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS acme_issuance_attempts;
-- +goose StatementEnd

-- +goose StatementBegin
-- Requests that reached the 'Failed' status have no equivalent in the old
-- schema. They are returned to 'Outstanding', which is where they sat before
-- issuance was attempted.
UPDATE certificate_requests SET status = 'Outstanding' WHERE status = 'Failed';

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
SELECT csr_id, csr, status, certificate_id, user_email FROM certificate_requests;

DROP TABLE certificate_requests;

ALTER TABLE certificate_requests_old RENAME TO certificate_requests;
-- +goose StatementEnd
