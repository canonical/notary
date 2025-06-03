package backend

type PKCS11 struct {
	Endpoint string
	Slot     string
	PIN      string
}

// Decrypt implements SecretBackend.
func (p PKCS11) Decrypt() {
	panic("unimplemented")
}

// Encrypt implements SecretBackend.
func (p PKCS11) Encrypt() {
	panic("unimplemented")
}

// Validate implements SecretBackend.
func (p PKCS11) Validate() {
	panic("unimplemented")
}
