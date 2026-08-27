package db

import (
	"errors"
	"fmt"
)

// ClusterSettings is the single-row cluster configuration stored in the
// replicated database. The designated ACME issuer is the only setting in the
// first HA release.
type ClusterSettings struct {
	ID               int64  `db:"id"`
	ACMEIssuerNodeID string `db:"acme_issuer_node_id"`
}

// SetACMEIssuerNodeID records which member may run ACME issuance.
func (db *DatabaseRepository) SetACMEIssuerNodeID(nodeID string) error {
	if nodeID == "" {
		return fmt.Errorf("failed to set ACME issuer: %w: node ID is empty", ErrInvalidInput)
	}

	_, err := db.Conn.PlainDB().Exec(
		`INSERT INTO cluster_settings (id, acme_issuer_node_id) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET acme_issuer_node_id=excluded.acme_issuer_node_id`,
		nodeID,
	)
	if err != nil {
		return fmt.Errorf("failed to set ACME issuer: %w: %w", ErrInternal, err)
	}
	return nil
}

// GetACMEIssuerNodeID returns the designated ACME issuer's dqlite node ID.
func (db *DatabaseRepository) GetACMEIssuerNodeID() (string, error) {
	row, err := GetOneEntity[ClusterSettings](db, db.stmts.GetClusterSettings, ClusterSettings{ID: 1})
	if err != nil {
		return "", err
	}
	if row.ACMEIssuerNodeID == "" {
		return "", fmt.Errorf("failed to get ACME issuer: %w", ErrNotFound)
	}
	return row.ACMEIssuerNodeID, nil
}

// ClearACMEIssuer is used by restore to drop the previous cluster's issuer
// before recording the restored node.
func (db *DatabaseRepository) ClearACMEIssuer() error {
	err := DeleteEntity[ClusterSettings](db, db.stmts.DeleteClusterSettings, ClusterSettings{ID: 1})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}
