-- +goose Up
-- +goose StatementBegin
-- Liveness and seal state, reported by each member about itself.
--
-- A member updates its own row on a timer; every other member reads it back
-- through replication, so no node has to reach any other node's API to report
-- on it. A heartbeat that stops advancing is what makes a member OFFLINE, and
-- writing one at all proves the member can still reach the Raft leader.
--
-- heartbeat is Unix seconds and NULL until the member's first beat. sealed
-- carries the member's own view of whether it has unwrapped its encryption key.
ALTER TABLE cluster_members ADD COLUMN heartbeat INTEGER;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE cluster_members ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cluster_members DROP COLUMN sealed;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE cluster_members DROP COLUMN heartbeat;
-- +goose StatementEnd
