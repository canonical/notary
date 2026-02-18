package encryption

import (
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/utils"
	"go.uber.org/zap"
)

func SetUpEncryptionKey(database *db.DatabaseRepository, backend EncryptionService, logger *zap.Logger) error {
	encryptionKeyFromDb, err := database.GetEncryptionKey()
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			encryptionKey, err := utils.GenerateAES256GCMEncryptionKey()
			if err != nil {
				return fmt.Errorf("failed to generate encryption key: %w", err)
			}
			logger.Info("Encryption key generated successfully")
			encryptedEncryptionKey, err := backend.Encrypt(encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt encryption key: %w", err)
			}
			logger.Info("Encryption key encrypted successfully using the configured encryption backend")
			err = database.CreateEncryptionKey(encryptedEncryptionKey)
			if err != nil {
				return fmt.Errorf("failed to store encryption key: %w", err)
			}
			// Set the encryption key on the database instance
			database.EncryptionKey = encryptionKey
			return nil
		}
		return fmt.Errorf("failed to get encryption key: %w", err)
	}
	logger.Info("Encryption key found in database")
	decryptedEncryptionKey, err := backend.Decrypt(encryptionKeyFromDb)
	if err != nil {
		return fmt.Errorf("failed to decrypt encryption key: %w", err)
	}
	database.EncryptionKey = decryptedEncryptionKey
	return nil
}
