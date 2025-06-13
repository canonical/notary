package encryption_backend

// EncryptionBackend defines the interface for encryption operations.
// Implementations should handle the encryption and decryption of sensitive data.
type EncryptionBackend interface {
	Decrypt(ciphertext []byte) ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
}

// NoEncryptionBackend is a no-op implementation of the EncryptionBackend interface.
// It used when encryption backend is configured to none.
type NoEncryptionBackend struct {
}

// Decrypt returns the ciphertext as is for NoEncryptionBackend.
func (n NoEncryptionBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// Encrypt returns the plaintext as is for NoEncryptionBackend.
func (n NoEncryptionBackend) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
