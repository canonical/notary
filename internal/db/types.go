package db

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
	CertificateAuthorityID int64  `db:"certificate_authority_id"`
	CRL                    string `db:"crl"`
	Enabled                bool   `db:"enabled"`
	PrivateKeyID           int64  `db:"private_key_id"`
	CertificateChain       string `db:"certificate_chain"`
	CSRPEM                 string `db:"csr"`
}

// Certificate contains information about a singular certificate in the database. Its IssuerID
// points to the ID of the certificate that issued this certificate. If it was self-signed, then
// the IssuerID will be 0.
type Certificate struct {
	CertificateID int64 `db:"certificate_id"`
	IssuerID      int64 `db:"issuer_id"`

	CertificatePEM string `db:"certificate"`
}

// CertificateRequest contains information about a request for Notary. This is a distinct object
// than the x.509 Certificate Signing Request which is contained within. Notary also keeps track
// of the status of this request, which may be pending, signed or rejected.
type CertificateRequest struct {
	CSR_ID int64 `db:"csr_id"`

	CSR           string `db:"csr"`
	Status        string `db:"status"`
	CertificateID int64  `db:"certificate_id"`
	UserID        int64  `db:"user_id"`
}

// CertificateRequestWithChain contains the same information as the CertificateRequest object,
// but this object contains the PEM encoded string chain of its assigned certificate directly embedded to
// the struct instead of an ID integer.
type CertificateRequestWithChain struct {
	CSR_ID int64 `db:"csr_id"`

	CSR              string `db:"csr"`
	Status           string `db:"status"`
	CertificateChain string `db:"certificate_chain"`
	UserID           int64  `db:"user_id"`
}

// PrivateKey contains the PEM encoded string of a private key. This object is only used in relation
// to a CertificateAuthority.
type PrivateKey struct {
	PrivateKeyID int64 `db:"private_key_id"`

	PrivateKeyPEM string `db:"private_key"`
}

// User contains information about a user of notary in the database. The permission can only be
// 1 for admin or 0 for regular user.
type User struct {
	ID int64 `db:"id"`

	Username       string `db:"username"`
	HashedPassword string `db:"hashed_password"`
	Permissions    int    `db:"permissions"`
}

type NumUsers struct {
	Count int `db:"count"`
}
