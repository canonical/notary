package encryption_backend

// EncryptionBackend defines the interface for encryption operations.
// Implementations should handle the encryption and decryption of sensitive data.
type EncryptionBackend interface {
	Decrypt(ciphertext []byte) ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
}
