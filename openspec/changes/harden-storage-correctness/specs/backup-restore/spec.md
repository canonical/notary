## ADDED Requirements

### Requirement: Restore replaces the database atomically
`notary restore` SHALL restore a backup archive by validating the extracted database and then replacing the database file atomically. A restore that fails at any point before the final replacement MUST leave the existing database and its sidecar files unchanged.

#### Scenario: Successful restore
- **WHEN** `notary restore` runs with a valid backup archive
- **THEN** the database file is replaced with the backup's contents, stale `-wal`/`-shm` sidecar files are removed, and a subsequent start serves the restored data

#### Scenario: Corrupt archive
- **WHEN** `notary restore` runs with an archive whose extracted contents are not a valid Notary database
- **THEN** the command fails with a clear error and the existing database is byte-for-byte unchanged

### Requirement: Restore uses a single SQLite implementation and no CGo
The restore path SHALL use only the primary pure-Go SQLite driver. The binary MUST NOT contain a second SQLite implementation, and restore MUST work in a `CGO_ENABLED=0` build.

#### Scenario: Pure-Go build restores successfully
- **WHEN** a Notary binary built with `CGO_ENABLED=0` runs `notary restore` with a valid archive
- **THEN** the restore succeeds
