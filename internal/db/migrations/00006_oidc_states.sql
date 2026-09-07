-- +goose Up
CREATE TABLE IF NOT EXISTS oidc_states
(
    state      TEXT PRIMARY KEY,
    user_agent TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS oidc_states;
