## ADDED Requirements

### Requirement: Committed writes survive node failure
All database writes SHALL be replicated via raft consensus and acknowledged only after commit on a quorum of voters. The permanent loss of any minority of voters MUST NOT lose an acknowledged write — including certificate issuance records, revocations, user changes, and audit-relevant state.

#### Scenario: Leader dies immediately after issuance
- **WHEN** a certificate is issued through the API and the leader node is destroyed immediately after the API call returns success
- **THEN** the issued certificate and its record are present on the new leader after election

### Requirement: Any node serves the full API
Every cluster member SHALL serve the complete Notary API, with writes transparently routed to the current raft leader. Clients MUST NOT need to know which node is leader.

#### Scenario: Write through a follower
- **WHEN** a revocation request is sent to a non-leader node
- **THEN** the request succeeds and the revocation is replicated to all members

### Requirement: Writes fail cleanly without quorum
When raft quorum is lost, API operations requiring a write (issuance, revocation, user management, configuration) SHALL fail promptly with an error identifying quorum loss — they must not hang indefinitely or partially apply.

#### Scenario: Two of three nodes down
- **WHEN** a certificate issuance request reaches the surviving node of a 3-node cluster that has lost quorum
- **THEN** the request fails with a clear quorum-related error within a bounded time

### Requirement: Distribution endpoints keep serving during quorum loss
Read-only distribution endpoints — CRL download and certificate/chain download — SHALL continue serving from the node's local replica during quorum loss, even though the data may be stale. This is safe because these artifacts are signed and carry their own validity windows.

#### Scenario: CRL served without quorum
- **WHEN** an external system fetches a CA's CRL from a surviving node of a quorum-less cluster
- **THEN** the last locally replicated signed CRL is returned successfully

### Requirement: Split-brain is impossible
At most one partition of the cluster SHALL be able to commit writes at any time. After a partition heals, all members MUST converge on the quorum side's history with no merged or forked state.

#### Scenario: Network partition
- **WHEN** a 3-node cluster partitions 2/1 and writes are attempted on both sides
- **THEN** only the majority side commits; after healing, the minority node converges to the majority's database with no lost or duplicated committed writes
