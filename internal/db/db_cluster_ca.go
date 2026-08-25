package db

import (
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

// ClusterCAKey is the cluster's internal CA private key, encrypted at rest with
// the database encryption key. There is only ever one row.
type ClusterCAKey struct {
	ID           int64  `db:"id"`
	EncryptedKey string `db:"encrypted_key"`
}

// CreateClusterCAKey stores the cluster CA private key.
//
// The key is deliberately kept here instead of on each node's disk. A member
// obtains it by being admitted and replicating, which means removing a member
// ends its access; handing it out over the token-authenticated join endpoint
// would instead turn a stolen join token into a permanent CA credential.
func (db *DatabaseRepository) CreateClusterCAKey(keyPEM []byte) error {
	if len(keyPEM) == 0 {
		return fmt.Errorf("failed to create cluster CA key: %w: key is empty", ErrInvalidInput)
	}

	encrypted, err := utils.Encrypt(string(keyPEM), db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt cluster CA key: %w", ErrInternal)
	}

	_, err = CreateEntity[ClusterCAKey](db, db.stmts.CreateClusterCAKey, ClusterCAKey{
		ID:           1,
		EncryptedKey: encrypted,
	})

	return err
}

// GetClusterCAKey returns the cluster CA private key.
func (db *DatabaseRepository) GetClusterCAKey() ([]byte, error) {
	row, err := GetOneEntity[ClusterCAKey](db, db.stmts.GetClusterCAKey, ClusterCAKey{ID: 1})
	if err != nil {
		return nil, err
	}

	decrypted, err := utils.Decrypt(row.EncryptedKey, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt cluster CA key: %w", err)
	}

	return []byte(decrypted), nil
}
