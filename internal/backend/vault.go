package backend

type Vault struct {
	Endpoint     string
	Path         string
	RoleID       string
	RoleSecretID string
	Token        string
}

// Decrypt implements SecretBackend.
func (v Vault) Decrypt() {
	panic("unimplemented")
}

// Encrypt implements SecretBackend.
func (v Vault) Encrypt() {
	panic("unimplemented")
}

// Validate implements SecretBackend.
func (v Vault) Validate() {
	panic("unimplemented")
}
