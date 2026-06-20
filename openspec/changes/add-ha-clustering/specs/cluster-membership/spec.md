## ADDED Requirements

### Requirement: Cluster initialization is explicit at first start
When started with an empty `storage-path`, Notary SHALL require exactly one of `--new-cluster` (`-n`) or `--join <token>` (`-j`) and SHALL refuse to start with a clear error if neither is given. `--new-cluster` bootstraps a 1-voter cluster that serves the full API immediately; single-node operation is a first-class, permanent mode with no further ceremony.

#### Scenario: Fresh single-node start
- **WHEN** Notary starts with an empty storage-path and `--new-cluster`
- **THEN** it logs that a new cluster was initialized, bootstraps a 1-voter cluster, and serves the full API

#### Scenario: Fresh start without an initialization flag
- **WHEN** Notary starts with an empty storage-path and neither `--new-cluster` nor `--join`
- **THEN** it exits with an error explaining that one of the two flags is required

### Requirement: Nodes join via single-use tokens
Adding a member SHALL be a two-step flow: an admin requests `POST /cluster/token` with `{"node-id": <id>}` on an existing member, which returns a base64-encoded join token that is single-use and expires after 5 minutes; the new node starts with `--join <token>` and a configured `node-id` matching the one the token was minted for. Tokens MUST be invalidated after use or expiry, and a join whose node-id does not match the token MUST be rejected.

#### Scenario: Successful join
- **WHEN** an operator or charm requests a token for `node-1` on an existing member and starts a new node configured as `node-1` with `--join <token>`
- **THEN** the new node joins the cluster, replicates the database, and serves the full API

#### Scenario: Reused or expired token
- **WHEN** a join is attempted with a token that was already used or is older than 5 minutes
- **THEN** the join is rejected

#### Scenario: Node-id mismatch
- **WHEN** a node configured as `node-2` attempts to join with a token minted for `node-1`
- **THEN** the join is rejected and the node logs the mismatch until the operator fixes the configuration

### Requirement: Cluster operations are automatable by a machine client
All cluster lifecycle operations SHALL be invocable non-interactively: bootstrap and join via the `--new-cluster`/`--join` startup flags, and token minting, member removal, and status via admin-authenticated API endpoints (`POST /cluster/token`, `POST /cluster/remove`, `GET /cluster/status`) with JSON responses, so they can be driven non-interactively by automation.

#### Scenario: Charm scales the application
- **WHEN** a charm reacts to a new peer unit by minting a token via the API on the leader unit and passing it to the new unit via peer relation data
- **THEN** the new unit joins without any human interaction

### Requirement: Member identity is stable across restarts
A node restarting with a non-empty `storage-path` SHALL rejoin the cluster as the same member, not as a new one, resuming its previous role. State recorded in the storage-path is authoritative: initialization flags and deviating `high-availability` config values MUST be ignored in its favor, with a warning logged. Rescheduling (e.g. a Kubernetes pod moving with its volume) MUST NOT grow the membership list.

#### Scenario: Pod reschedule
- **WHEN** a node's process is killed and restarted with the same storage-path
- **THEN** cluster membership count is unchanged and the node resumes its previous identity

#### Scenario: Restart automation passes stale flags
- **WHEN** an existing node is restarted with `--new-cluster` or `--join`, or with config values that deviate from the recorded cluster state
- **THEN** the flags and deviating values are ignored in favor of the storage-path state and a warning is logged

### Requirement: Members can be removed and quorum arithmetic maintained
`POST /cluster/remove` with `{"node-id": <id>}` SHALL remove the named member regardless of its status: a live member is removed gracefully (leadership/voter handover first), a down member is removed forcibly. After removal the node is permanently disconnected and its storage-path can be safely deleted. The cluster SHALL manage voter/standby roles automatically so that voter count follows the recommended odd-number pattern as the cluster grows and shrinks. Deleting a storage-path is NOT a supported removal mechanism.

#### Scenario: Graceful scale-down
- **WHEN** `POST /cluster/remove` targets a live member
- **THEN** the member hands over any leadership/voter role, is removed from the membership, and remaining nodes retain quorum

#### Scenario: Permanently lost node
- **WHEN** a member machine is destroyed without a graceful removal and `POST /cluster/remove` targets its node-id
- **THEN** the member is forcibly removed and the cluster returns to a healthy voter configuration

### Requirement: Graceful shutdown hands over roles
On SIGTERM/SIGINT a node SHALL hand over dqlite leadership and voter responsibilities before exiting, so rolling restarts do not cause avoidable election outages.

#### Scenario: Rolling restart
- **WHEN** nodes of a 3-node cluster are restarted one at a time with graceful shutdown
- **THEN** write availability is maintained throughout (excluding sub-second leader handover)
