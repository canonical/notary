package backend

type EncryptionBackend interface {
	Decrypt(ciphertext string) (string, error)
	Encrypt(plaintext string) (string, error)
}

type None struct {
}

// Decrypt implements SecretBackend.
func (n None) Decrypt() {
	panic("unimplemented")
}

// Encrypt implements SecretBackend.
func (n None) Encrypt() {
	panic("unimplemented")
}
