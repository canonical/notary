package db

// AES256GCMEncryptionKey contains the string of an AES256-GCM encryption key.
// This object is the master key that encrypts all private data in the database.
type AES256GCMEncryptionKey struct {
	EncryptionKeyID int64  `db:"encryption_key_id"`
	EncryptionKey   string `db:"encryption_key"`
}

// JWTSecret contains the string of a JWT secret.
// This secret is used to sign and verify JSON Web Tokens (JWTs) used for authentication and authorization.
type JWTSecret struct {
	ID              int64  `db:"id"`
	EncryptedSecret string `db:"encrypted_secret"`
}

// CSRStatus represents the status of a Notary Certificate Signing Request. This is independent of the
// status of the certificate itself, and exists for admins to keep track of the request's lifecycle.
type CSRStatus string

const (
	CSRStatusPending  = "pending"
	CSRStatusActive   = "active"
	CSRStatusRejected = "rejected"
	CSRStatusRevoked  = "revoked"
)

// CertificateRequest contains information about a request for Notary. This is a distinct object
// than the x.509 Certificate Signing Request which is contained within. Notary also keeps track
// of the status of this request, which may be pending, active, rejected or revoked.
type CertificateRequest struct {
	CSR_ID  int64 `db:"csr_id"`
	OwnerID int64 `db:"owner_id"`

	CSR    string    `db:"csr"`
	Status CSRStatus `db:"status"`

	CertificateID int64 `db:"certificate_id"`
}

// CertificateRequestWithChain contains the same information as the CertificateRequest object,
// but this object contains the PEM encoded string chain of its assigned certificate directly embedded to
// the struct instead of an ID integer.
type CertificateRequestWithChain struct {
	CSR_ID  int64 `db:"csr_id"`
	OwnerID int64 `db:"owner_id"`

	CSR    string    `db:"csr"`
	Status CSRStatus `db:"status"`

	CertificateChain string `db:"certificate_chain"`
}

// Certificate contains information about a singular certificate in the database. Its IssuerID
// points to the ID of the certificate that issued this certificate. If it was self-signed, then
// the IssuerID will be 0.
type Certificate struct {
	CertificateID int64 `db:"certificate_id"`
	IssuerID      int64 `db:"issuer_id"`

	CertificatePEM string `db:"certificate"`
}

const CAMaxExpiryYears = 1

// CertificateAuthority contains information about a CA, identified by the contents
// of the CSR that it was created with. It has an assigned private key and optionally,
// a fulfilled certificate and an associated CRL.
type CertificateAuthority struct {
	CertificateAuthorityID int64 `db:"certificate_authority_id"`

	CRL     string `db:"crl"`
	Enabled bool   `db:"enabled"`

	PrivateKeyID  int64 `db:"private_key_id"`
	CertificateID int64 `db:"certificate_id"`
	CSRID         int64 `db:"csr_id"`
}

// CertificateAuthorityDenormalized contains the same information as the CertificateAuthority
// object, but this object contains the PEM encoded strings directly embedded to the struct
// instead of an ID integer.
type CertificateAuthorityDenormalized struct {
	CertificateAuthorityID int64 `db:"certificate_authority_id"`

	CRL     string `db:"crl"`
	Enabled bool   `db:"enabled"`

	PrivateKeyID     int64  `db:"private_key_id"`
	CertificateChain string `db:"certificate_chain"`
	CSRPEM           string `db:"csr"`
}

// PrivateKey contains the PEM encoded string of a private key. This object is only used in relation
// to a CertificateAuthority.
type PrivateKey struct {
	PrivateKeyID int64 `db:"private_key_id"`

	PrivateKeyPEM string `db:"private_key"`
}

// RoleID represents the role of a user in Notary.
type RoleID int

const (
	RoleAdmin                RoleID = 0
	RoleCertificateManager   RoleID = 1
	RoleCertificateRequestor RoleID = 2
	RoleReadOnly             RoleID = 3
)

// User contains information about a user of notary in the database.
type User struct {
	ID int64 `db:"id"`

	Username       string `db:"username"`
	HashedPassword string `db:"hashed_password"`
	RoleID         RoleID `db:"role_id"`
}

type NumUsers struct {
	Count int `db:"count"`
}
