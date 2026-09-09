-- +goose Up
ALTER TABLE cluster_members ADD COLUMN api_address TEXT NOT NULL DEFAULT '';

-- +goose Down
-- DROP COLUMN needs SQLite 3.35+. dqlite's bundled SQLite may be older, so this
-- is a no-op. Reverting api_address is not required for rolling upgrades.
SELECT 1;
