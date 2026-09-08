package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const oidcStateTTL = 5 * time.Minute

func (db *DatabaseRepository) StoreOIDCState(state, userAgent string) error {
	if db == nil || db.Conn == nil {
		return fmt.Errorf("database is not open")
	}
	if state == "" {
		return fmt.Errorf("%w: oidc state is empty", ErrInvalidInput)
	}
	created := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Conn.PlainDB().ExecContext(context.Background(), `
		INSERT INTO oidc_states (state, user_agent, created_at) VALUES (?, ?, ?)
		ON CONFLICT(state) DO UPDATE SET user_agent = excluded.user_agent, created_at = excluded.created_at
	`, state, userAgent, created)
	if err != nil {
		return fmt.Errorf("%w: store oidc state: %v", ErrInternal, err)
	}
	return nil
}

func (db *DatabaseRepository) ValidateOIDCState(state, userAgent string) bool {
	if db == nil || db.Conn == nil || state == "" {
		return false
	}
	sqldb := db.Conn.PlainDB()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false
	}
	claim := "claimed:" + hex.EncodeToString(nonce[:]) + ":" + state
	res, err := sqldb.ExecContext(context.Background(), `UPDATE oidc_states SET state = ? WHERE state = ?`, claim, state)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return false
	}
	var storedUA, createdAt string
	err = sqldb.QueryRowContext(context.Background(), `SELECT user_agent, created_at FROM oidc_states WHERE state = ?`, claim).Scan(&storedUA, &createdAt)
	_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM oidc_states WHERE state = ?`, claim)
	if err != nil {
		return false
	}
	created, parseErr := time.Parse(time.RFC3339, createdAt)
	if parseErr != nil || time.Since(created) > oidcStateTTL {
		return false
	}
	return storedUA == userAgent
}

func (db *DatabaseRepository) CleanupOIDCStates() error {
	if db == nil || db.Conn == nil {
		return nil
	}
	cutoff := time.Now().UTC().Add(-oidcStateTTL).Format(time.RFC3339)
	_, err := db.Conn.PlainDB().ExecContext(context.Background(), `DELETE FROM oidc_states WHERE created_at < ?`, cutoff)
	return err
}

func (db *DatabaseRepository) CountOIDCStates() int {
	if db == nil || db.Conn == nil {
		return 0
	}
	var n int
	_ = db.Conn.PlainDB().QueryRowContext(context.Background(), `SELECT COUNT(1) FROM oidc_states`).Scan(&n)
	return n
}
