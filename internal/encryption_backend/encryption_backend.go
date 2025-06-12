package encryption_backend

// EncryptionBackend defines the interface for encryption operations.
// Implementations should handle the encryption and decryption of sensitive data.
type EncryptionBackend interface {
	Decrypt(ciphertext []byte) ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
}

// NoEncryptionBackend is a no-op implementation of the EncryptionBackend interface.
// It used when no encryption backend is configured.
type NoEncryptionBackend struct {
}

// Decrypt implements SecretBackend.
func (n NoEncryptionBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// Encrypt implements SecretBackend.
func (n NoEncryptionBackend) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
