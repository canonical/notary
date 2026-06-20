## ADDED Requirements

### Requirement: Independent migration bookkeeping per subsystem
Notary's own schema migrations and the embedded OpenFGA's schema migrations SHALL be tracked in separate version tables in the database. Applying one subsystem's migrations MUST NOT affect the recorded version or applicability of the other subsystem's migrations.

#### Scenario: Notary migration added after OpenFGA migrations applied
- **WHEN** a database already has Notary migrations 1–2 and OpenFGA migrations applied, and a new Notary migration 3 ships in an upgraded binary
- **THEN** migration 3 is detected as pending and applied on startup (or via `notary migrate up`)

#### Scenario: Fresh database initialization
- **WHEN** Notary starts against an empty database with migrations enabled
- **THEN** Notary's migrations and OpenFGA's migrations are both applied, each recorded in its own version table

### Requirement: Migration state must not depend on global mutable configuration
Migration execution SHALL NOT rely on process-global mutable state (such as a shared package-level filesystem or dialect setting) in a way that makes correctness depend on the order in which subsystems initialize.

#### Scenario: Subsystems initialize in any order
- **WHEN** Notary's migration runner and OpenFGA's migration runner execute in either order within the same process
- **THEN** both apply their own migration sets correctly

### Requirement: Outdated schema is reported, not silently tolerated
When migrations are pending and automatic migration is disabled, Notary SHALL refuse to start and report which subsystem's schema is outdated.

#### Scenario: Pending Notary migration with auto-migrate disabled
- **WHEN** Notary starts with `--migrate-database` not set and a pending Notary migration exists
- **THEN** startup fails with an error instructing the operator to run `notary migrate up`
