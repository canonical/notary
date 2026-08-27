package db

import (
	"github.com/canonical/sqlair"
	"go.uber.org/zap"
)

type DatabaseOpts struct {
	DatabasePath string
	Logger       *zap.Logger
}

// DatabaseRepository is the object used to communicate with the established repository.
type DatabaseRepository struct {
	Conn  *sqlair.DB
	stmts *Statements

	Path          string
	EncryptionKey []byte
	JWTSecret     []byte
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
	// SerialNumber is the lowercase hexadecimal representation of the x.509 serial
	// number carried inside CertificatePEM. It is stored in its own column so the
	// database can enforce uniqueness.
	SerialNumber string `db:"serial_number"`
}

// CertificateRequest contains information about a request for Notary. This is a distinct object
// than the x.509 Certificate Signing Request which is contained within. Notary also keeps track
// of the status of this request, which may be pending, signed or rejected.
type CertificateRequest struct {
	CSR_ID int64 `db:"csr_id"`

	CSR           string `db:"csr"`
	Status        string `db:"status"`
	CertificateID int64  `db:"certificate_id"`
	UserEmail     string `db:"user_email"`
}

// CertificateRequestWithChain contains the same information as the CertificateRequest object,
// but this object contains the PEM encoded string chain of its assigned certificate directly embedded to
// the struct instead of an ID integer.
type CertificateRequestWithChain struct {
	CSR_ID int64 `db:"csr_id"`

	CSR              string `db:"csr"`
	Status           string `db:"status"`
	CertificateChain string `db:"certificate_chain"`
	UserEmail        string `db:"user_email"`
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

	Email          string  `db:"email"`
	HashedPassword *string `db:"hashed_password"` // Nullable for OIDC-only users
	RoleID         RoleID  `db:"role_id"`
	OIDCSubject    *string `db:"oidc_subject"` // OIDC provider's subject identifier
	OIDCIssuer     *string `db:"oidc_issuer"`  // Issuer that minted OIDCSubject; identity is (issuer, subject)
}

// HasPassword checks if a user has a local password set
func (u *User) HasPassword() bool {
	return u.HashedPassword != nil && *u.HashedPassword != ""
}

// HasOIDC checks if a user has an OIDC identity linked
func (u *User) HasOIDC() bool {
	return u.OIDCSubject != nil && *u.OIDCSubject != ""
}

type NumUsers struct {
	Count int `db:"count"`
}

type ACMEAccount struct {
	ID               int64  `db:"id"`
	Email            string `db:"email"`
	DirectoryURL     string `db:"directory_url"`
	PrivateKeyPEM    string `db:"private_key"`
	RegistrationURI  string `db:"registration_uri"`
	RegistrationBody string `db:"registration_body"`
}

type ACMEServer struct {
	ID            int64  `db:"id"`
	Name          string `db:"name"`
	DirectoryURL  string `db:"directory_url"`
	Email         string `db:"email"`
	DNSProvider   string `db:"dns_provider"`
	EnvVars       string `db:"env_vars"`
	Active        bool   `db:"active"`
	ACMEAccountID *int64 `db:"acme_account_id"`
}

// ClusterJoinToken is a single-use, time-limited credential that authorizes one
// node's join preflight. It is bound to that node's identity and is not the
// dqlite admission boundary.
//
// Only the token's SHA-256 hash is stored, never the token itself: possessing a
// database dump must not be enough to complete the join workflow.
type ClusterJoinToken struct {
	ID int64 `db:"id"`

	TokenHash string `db:"token_hash"`
	Identity  string `db:"identity"`
	CreatedAt int64  `db:"created_at"`
	ExpiresAt int64  `db:"expires_at"`
	// UsedAt is nil until the token is redeemed. A token is valid exactly once.
	UsedAt *int64 `db:"used_at"`
}

// ClusterMember maps a dqlite node ID to the name an operator gave it when it
// joined. dqlite itself only knows IDs, addresses and roles.
type ClusterMember struct {
	ID int64 `db:"id"`

	// NodeID is dqlite's node ID rendered in decimal. It is stored as text
	// because dqlite node IDs are uint64 and overflow SQLite's signed INTEGER.
	NodeID   string `db:"node_id"`
	Name     string `db:"name"`
	Address  string `db:"address"`
	JoinedAt int64  `db:"joined_at"`

	// Heartbeat is when the member last reported itself alive, in Unix seconds,
	// or nil if it never has. A member writes its own; everyone else reads it
	// back through replication.
	Heartbeat *int64 `db:"heartbeat"`

	// Sealed is the member's own last report of whether it still has to unwrap
	// its encryption key.
	Sealed bool `db:"sealed"`
}

// ACMEIssuanceAttempt records that a certificate request has been handed to an
// ACME provider and is being polled by a specific node. The row lives only for
// the duration of the attempt; one that outlives its owner marks an issuance
// interrupted by that node's failure.
type ACMEIssuanceAttempt struct {
	CSRID int64 `db:"csr_id"`

	// NodeID is the dqlite node ID of the node running the attempt, in decimal.
	// It is empty for an unclustered deployment, which has no node IDs.
	NodeID    string `db:"node_id"`
	StartedAt int64  `db:"started_at"`
}
