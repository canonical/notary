package encryption

// EncryptionService defines the interface for encryption operations.
// Implementations should handle the encryption and decryption of sensitive data.
type EncryptionService interface {
	Decrypt(ciphertext []byte) ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
}

type EncryptionRepository struct {
	Service EncryptionService
	Type    EncryptionBackendType

	// SealState tracks whether this node has unwrapped the data encryption key
	// yet. It is nil outside the server, where the unwrap is synchronous.
	SealState *SealState
}

// Sealed reports whether this node still has to unwrap its data encryption key.
func (r *EncryptionRepository) Sealed() bool {
	if r == nil {
		return false
	}
	return r.SealState.Sealed()
}

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)
