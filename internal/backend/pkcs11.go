package backend

type PKCS11 struct {
	Endpoint string
	Slot     string
	PIN      string
}

// Decrypt implements SecretBackend.
func (p PKCS11) Decrypt(ciphertext string) (string, error) {
	panic("unimplemented")
}

// Encrypt implements SecretBackend.
func (p PKCS11) Encrypt(plaintext string) (string, error) {
	panic("unimplemented")
}

// Validate implements SecretBackend.
func (p PKCS11) Validate() {
	panic("unimplemented")
}
