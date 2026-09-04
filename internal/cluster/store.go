package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func upsertMember(ctx context.Context, sqldb *sql.DB, name, address string) error {
	_, err := sqldb.ExecContext(ctx, `
		INSERT INTO cluster_members (name, address) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET address = excluded.address
	`, name, address)
	if err != nil {
		return fmt.Errorf("record cluster member %q: %w", name, err)
	}
	return nil
}

func deleteMemberName(ctx context.Context, sqldb *sql.DB, name string) error {
	_, err := sqldb.ExecContext(ctx, `DELETE FROM cluster_members WHERE name = ?`, name)
	return err
}

func namesByAddress(ctx context.Context, sqldb *sql.DB) (map[string]string, error) {
	rows, err := sqldb.QueryContext(ctx, `SELECT name, address FROM cluster_members`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, address string
		if err := rows.Scan(&name, &address); err != nil {
			return nil, err
		}
		out[address] = name
	}
	return out, rows.Err()
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

func consumeJoinToken(ctx context.Context, sqldb *sql.DB, name, secret string) error {
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
