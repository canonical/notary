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
}

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)
