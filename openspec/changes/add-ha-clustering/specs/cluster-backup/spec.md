## ADDED Requirements

### Requirement: Backup captures a consistent snapshot from the cluster
`notary backup` (CLI and API) SHALL produce a consistent point-in-time dump of the database taken via the dqlite leader, regardless of which node the command runs on. The produced artifact MUST be restorable on its own, without raft log or state-directory internals.

#### Scenario: Backup on a follower
- **WHEN** a backup is triggered on a non-leader member of a healthy cluster
- **THEN** a complete, consistent backup archive is produced

### Requirement: Restore recreates a cluster from a backup
Restore SHALL be a documented disaster-recovery flow: form a fresh 1-node cluster from a backup archive, then rejoin the remaining nodes. Restoring into a running multi-node cluster in place is NOT required, but attempting it MUST fail with guidance rather than corrupt state.

#### Scenario: Disaster recovery
- **WHEN** all cluster nodes are lost and an operator runs the restore flow with the latest backup archive on a fresh machine
- **THEN** a healthy 1-node cluster starts with the backed-up data, and new members can join it

### Requirement: Existing SQLite databases can be imported
Starting Notary with `--new-cluster --from-db <path>` on an empty storage-path SHALL import a pre-cluster Notary SQLite database file into the fresh 1-node cluster, preserving all data including CAs, private keys, certificates, users, and OpenFGA tuples.

#### Scenario: Upgrade from single-file deployment
- **WHEN** an operator starts `--new-cluster --from-db` with the SQLite file of a previous Notary release (with `harden-storage-correctness` migrations applied)
- **THEN** the cluster serves the same data, existing user credentials work, and previously issued certificates and CRLs are intact
