package backend

type SecretBackend interface {
	Decrypt()
	Encrypt()
	Validate()
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

// Validate implements SecretBackend.
func (n None) Validate() {
	panic("unimplemented")
}
