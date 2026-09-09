package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func upsertMember(ctx context.Context, sqldb *sql.DB, name, address, apiAddress string) error {
	_, err := sqldb.ExecContext(ctx, `
		INSERT INTO cluster_members (name, address, api_address) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET address = excluded.address, api_address = excluded.api_address
	`, name, address, apiAddress)
	if err != nil {
		return fmt.Errorf("record cluster member %q: %w", name, err)
	}
	return nil
}

func deleteMemberName(ctx context.Context, sqldb *sql.DB, name string) error {
	_, err := sqldb.ExecContext(ctx, `DELETE FROM cluster_members WHERE name = ?`, name)
	return err
}

func deleteMembersNotIn(ctx context.Context, sqldb *sql.DB, keep map[string]struct{}) error {
	stale, err := staleMemberNames(ctx, sqldb, keep)
	if err != nil {
		return err
	}
	for _, name := range stale {
		if err := deleteMemberName(ctx, sqldb, name); err != nil {
			return err
		}
	}
	return nil
}

func staleMemberNames(ctx context.Context, sqldb *sql.DB, keep map[string]struct{}) ([]string, error) {
	rows, err := sqldb.QueryContext(ctx, `SELECT name, address FROM cluster_members`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var stale []string
	for rows.Next() {
		var name, address string
		if err := rows.Scan(&name, &address); err != nil {
			return nil, err
		}
		if _, ok := keep[address]; !ok {
			stale = append(stale, name)
		}
	}
	return stale, rows.Err()
}

type memberRecord struct {
	name       string
	apiAddress string
}

func recordsByAddress(ctx context.Context, sqldb *sql.DB) (map[string]memberRecord, error) {
	rows, err := sqldb.QueryContext(ctx, `SELECT name, address, api_address FROM cluster_members`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]memberRecord{}
	for rows.Next() {
		var address string
		var rec memberRecord
		if err := rows.Scan(&rec.name, &address, &rec.apiAddress); err != nil {
			return nil, err
		}
		out[address] = rec
	}
	return out, rows.Err()
}

// LookupAPIAddress returns the HTTPS address recorded for a dqlite member.
// fallback is empty when a stored api_address is used; otherwise it explains
// why the caller should log and show clusterAddress instead.
func LookupAPIAddress(ctx context.Context, sqldb *sql.DB, clusterAddress string) (addr string, fallback string) {
	if sqldb == nil {
		return clusterAddress, "database is not open"
	}
	if clusterAddress == "" {
		return "", "leader dqlite address is empty"
	}
	var api string
	err := sqldb.QueryRowContext(ctx, `SELECT api_address FROM cluster_members WHERE address = ?`, clusterAddress).Scan(&api)
	if err == sql.ErrNoRows {
		return clusterAddress, "no cluster_members row for leader"
	}
	if err != nil {
		return clusterAddress, err.Error()
	}
	if strings.TrimSpace(api) == "" {
		return clusterAddress, "leader api_address is empty"
	}
	return api, ""
}

// APIAddressFor returns the HTTPS address recorded for a dqlite member.
// If none is stored, it returns clusterAddress so callers can still show something.
func APIAddressFor(ctx context.Context, sqldb *sql.DB, clusterAddress string) string {
	addr, _ := LookupAPIAddress(ctx, sqldb, clusterAddress)
	return addr
}

func addressForName(ctx context.Context, sqldb *sql.DB, name string) (string, error) {
	var address string
	err := sqldb.QueryRowContext(ctx, `SELECT address FROM cluster_members WHERE name = ?`, name).Scan(&address)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("%w %q", ErrMemberNotFound, name)
	}
	if err != nil {
		return "", err
	}
	return address, nil
}

func memberNameExists(ctx context.Context, sqldb *sql.DB, name string) (bool, error) {
	var n int
	err := sqldb.QueryRowContext(ctx, `SELECT COUNT(1) FROM cluster_members WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

func putJoinToken(ctx context.Context, sqldb *sql.DB, name, secret string, expires time.Time) error {
	_, err := sqldb.ExecContext(ctx, `
		INSERT INTO cluster_join_tokens (name, secret, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET secret = excluded.secret, expires_at = excluded.expires_at
	`, name, secret, expires.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store join token: %w", err)
	}
	return nil
}

// RestoreJoinToken puts a consumed ticket back so the joiner can retry redeem
// when membership listing failed after consume (for example a leadership change).
func RestoreJoinToken(ctx context.Context, sqldb *sql.DB, token JoinToken) error {
	if token.ServerName == "" || token.Secret == "" {
		return fmt.Errorf("join token is incomplete")
	}
	return putJoinToken(ctx, sqldb, token.ServerName, token.Secret, token.ExpiresAt)
}

func consumeJoinToken(ctx context.Context, sqldb *sql.DB, name, secret string) error {
	// Single statement so the one-time guarantee holds under concurrent redeems.
	// expires_at compares lexicographically, which is only correct because both
	// sides are RFC3339 in UTC. The secret match is not constant-time; it is 32
	// random bytes, so a timing oracle is not a practical path to guessing it.
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := sqldb.ExecContext(ctx, `
		DELETE FROM cluster_join_tokens
		WHERE name = ? AND secret = ? AND expires_at > ?
	`, name, secret, now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var storedExpires string
	err = sqldb.QueryRowContext(ctx, `SELECT expires_at FROM cluster_join_tokens WHERE name = ?`, name).Scan(&storedExpires)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: join token for %q not found or already used", ErrJoinTokenNotFound, name)
	}
	if err != nil {
		return err
	}
	exp, err := time.Parse(time.RFC3339, storedExpires)
	if err != nil {
		return fmt.Errorf("join token expiry: %w", err)
	}
	if !time.Now().After(exp) {
		return fmt.Errorf("%w: join token for %q is invalid", ErrJoinTokenInvalid, name)
	}
	return fmt.Errorf("%w: join token for %q has expired", ErrJoinTokenExpired, name)
}
