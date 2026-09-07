package encryption

import (
	"errors"
	"fmt"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/utils"
	"go.uber.org/zap"
)

func SetUpEncryptionKey(database *db.DatabaseRepository, backend EncryptionService, logger *zap.Logger) error {
	const attempts = 8
	var encryptedCandidate []byte
	var plaintext []byte
	var last error

	for i := range attempts {
		encryptionKeyFromDb, err := database.GetEncryptionKey()
		switch {
		case err == nil:
			logger.Info("Encryption key found in database")
			decryptedEncryptionKey, err := backend.Decrypt(encryptionKeyFromDb)
			if err != nil {
				return fmt.Errorf("failed to decrypt encryption key: %w", err)
			}
			database.EncryptionKey = decryptedEncryptionKey
			return nil
		case errors.Is(err, db.ErrNotFound):
		case errors.Is(err, db.ErrInternal):
			last = err
			time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
			continue
		default:
			return fmt.Errorf("failed to get encryption key: %w", err)
		}

		if encryptedCandidate == nil {
			var genErr error
			plaintext, genErr = utils.GenerateAES256GCMEncryptionKey()
			if genErr != nil {
				return fmt.Errorf("failed to generate encryption key: %w", genErr)
			}
			logger.Info("Encryption key generated successfully")
			encryptedCandidate, genErr = backend.Encrypt(plaintext)
			if genErr != nil {
				return fmt.Errorf("failed to encrypt encryption key: %w", genErr)
			}
			logger.Info("Encryption key encrypted successfully using the configured encryption backend")
		}

		switch err = database.CreateEncryptionKey(encryptedCandidate); {
		case err == nil:
			database.EncryptionKey = plaintext
			return nil
		case errors.Is(err, db.ErrAlreadyExists):
			last = err
		case errors.Is(err, db.ErrInternal):
			last = err
			time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
		default:
			return fmt.Errorf("failed to store encryption key: %w", err)
		}
	}
	return fmt.Errorf("failed to set up encryption key: %w", last)
}
