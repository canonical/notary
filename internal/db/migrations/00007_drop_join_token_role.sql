-- +goose Up
-- +goose StatementBegin
-- The role a join token asked for never had any effect.
--
-- dqlite assigns Raft roles itself: it keeps the configured number of voters
-- filled and parks the rest as stand-bys, promoting one whenever a voter is
-- lost. A token could not override that, so a "standby" token still produced a
-- voter whenever the cluster was short of them. Rather than fight dqlite's role
-- management, the token no longer claims to influence it; `notary cluster
-- promote` remains the way to force a role immediately.
ALTER TABLE cluster_join_tokens DROP COLUMN role;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cluster_join_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'standby';
-- +goose StatementEnd
