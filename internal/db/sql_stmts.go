package db

import (
	"github.com/canonical/sqlair"
)

const (
	// Table definition SQL Strings
	queryCreateCertificateRequestsTable = `
		CREATE TABLE IF NOT EXISTS certificate_requests (
		    csr_id INTEGER PRIMARY KEY AUTOINCREMENT,

			csr TEXT NOT NULL UNIQUE,
			certificate_id INTEGER,
			user_id INTEGER,
			status TEXT DEFAULT 'Outstanding',

			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,

			CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active')),
			CHECK (NOT (certificate_id == NULL AND status == 'Active' )),
			CHECK (NOT (certificate_id != NULL AND status == 'Outstanding'))
	        CHECK (NOT (certificate_id != NULL AND status == 'Rejected'))
	        CHECK (NOT (certificate_id != NULL AND status == 'Revoked'))
    )`
	queryCreateCertificatesTable = `
		CREATE TABLE IF NOT EXISTS certificates (
		    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,
			issuer_id INTEGER,

			certificate TEXT NOT NULL UNIQUE
	)`
	queryCreateCertificateAuthoritiesTable = `
		CREATE TABLE IF NOT EXISTS certificate_authorities (
		    certificate_authority_id INTEGER PRIMARY KEY AUTOINCREMENT,

			crl TEXT,
			status TEXT DEFAULT 'Pending',

			private_key_id INTEGER,
			certificate_id INTEGER,
			csr_id INTEGER NOT NULL UNIQUE,

			CHECK (status IN ('active', 'expired', 'pending', 'legacy')),
			CHECK (NOT (certificate_id == NULL AND status == 'active' )),
			CHECK (NOT (certificate_id != NULL AND status == 'pending'))
	        CHECK (NOT (certificate_id != NULL AND status == 'expired'))
	)`
	queryCreatePrivateKeysTable = `
		CREATE TABLE IF NOT EXISTS private_keys (
		    private_key_id INTEGER PRIMARY KEY AUTOINCREMENT,

			private_key TEXT NOT NULL UNIQUE
	)`
	queryCreateUsersTable = `
		CREATE TABLE IF NOT EXISTS users (
	 		id INTEGER PRIMARY KEY AUTOINCREMENT,

			username TEXT NOT NULL UNIQUE,
			hashed_password TEXT NOT NULL,
			permissions INTEGER CHECK (permissions IN (0,1)),

			CHECK (trim(username) != ''),
			CHECK (trim(hashed_password) != '')
	)`
	queryCreateEncryptionKeysTable = `
		CREATE TABLE IF NOT EXISTS encryption_keys (
		    encryption_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
			encryption_key TEXT NOT NULL UNIQUE
	)`
	queryCreateJWTSecretTable = `
		CREATE TABLE IF NOT EXISTS jwt_secret (
			id INTEGER PRIMARY KEY CHECK (id = 1), -- Ensures only one row
			encrypted_secret TEXT NOT NULL
	)`
)

const (
	// // // // // // // // // // // // //
	//  Certificate Request SQL Strings //
	// // // // // // // // // // // // //
	listCertificateRequestsStmt           = "SELECT &CertificateRequest.* FROM certificate_requests"
	listCertificateRequestsWithoutCASStmt = "SELECT csrs.&CertificateRequest.csr_id, csrs.&CertificateRequest.csr, csrs.&CertificateRequest.status, csrs.&CertificateRequest.certificate_id FROM certificate_requests csrs LEFT JOIN certificate_authorities cas ON csrs.csr_id = cas.csr_id WHERE cas.certificate_authority_id IS NULL"
	getCertificateRequestStmt             = "SELECT &CertificateRequest.* FROM certificate_requests WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	updateCertificateRequestStmt          = "UPDATE certificate_requests SET certificate_id=$CertificateRequest.certificate_id, status=$CertificateRequest.status WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	createCertificateRequestStmt          = "INSERT INTO certificate_requests (csr, user_id) VALUES ($CertificateRequest.csr, $CertificateRequest.user_id)"
	deleteCertificateRequestStmt          = "DELETE FROM certificate_requests WHERE csr_id=$CertificateRequest.csr_id or csr=$CertificateRequest.csr"

	listCertificateRequestsWithCertificatesStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT
        csr.csr_id,
        csr.csr,
		csr.status,
		csr.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM certificate_requests csr
    LEFT JOIN certificates cert
      ON csr.certificate_id = cert.certificate_id

    UNION ALL

    -- Recursive Query: Find the issuer certificate in the certificates table
    SELECT
        cc.csr_id,
        cc.csr,
		cc.status,
		cc.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        cc.chain || CHAR(10) || cert.certificate AS chain
    FROM certificates cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT
	&CertificateRequestWithChain.csr_id,
	&CertificateRequestWithChain.csr,
	&CertificateRequestWithChain.status,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain
WHERE chain = '' OR issuer_id = 0`
	listCertificateRequestsWithCertificatesWithoutCASStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT
        csr.csr_id,
        csr.csr,
        csr.status,
        csr.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM certificate_requests csr
    LEFT JOIN certificates cert
      ON csr.certificate_id = cert.certificate_id

    UNION ALL

    -- Recursive Query: Find the issuer certificate in the certificates table
    SELECT
        cc.csr_id,
        cc.csr,
        cc.status,
        cc.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        cc.chain || CHAR(10) || cert.certificate AS chain
    FROM certificates cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT
	cc.&CertificateRequestWithChain.csr_id,
	cc.&CertificateRequestWithChain.csr,
	cc.&CertificateRequestWithChain.status,
	cc.&CertificateRequestWithChain.user_id,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain cc
LEFT JOIN certificate_authorities cas ON cc.csr_id = cas.csr_id
WHERE cas.certificate_authority_id IS NULL AND (chain = '' OR issuer_id = 0)`

	getCertificateRequestWithCertificateStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT
        csr.csr_id,
        csr.csr,
		csr.status,
		csr.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM certificate_requests csr
    LEFT JOIN certificates cert
      ON csr.certificate_id = cert.certificate_id

    UNION ALL

    -- Recursive Query: Find the issuer certificate in the certificates table
    SELECT
        cc.csr_id,
        cc.csr,
		cc.status,
		cc.user_id,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        cc.chain || CHAR(10) || cert.certificate AS chain
    FROM certificates cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT
	&CertificateRequestWithChain.csr_id,
	&CertificateRequestWithChain.csr,
	&CertificateRequestWithChain.status,
	&CertificateRequestWithChain.user_id,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain
WHERE (csr_id = $CertificateRequestWithChain.csr_id OR csr = $CertificateRequestWithChain.csr) AND (chain = '' OR issuer_id = 0)`

	// // // // // // // // // //
	// Certificate SQL Strings //
	// // // // // // // // // //
	createCertificateStmt   = "INSERT INTO certificates (certificate, issuer_id) VALUES ($Certificate.certificate, $Certificate.issuer_id)"
	addCertificateToCSRStmt = "UPDATE certificates SET certificate_id=$Certificate.certificate_id, status=$CertificateRequest.status WHERE id==$CertificateRequest.id or csr==$CertificateRequest.csr"
	getCertificateStmt      = "SELECT &Certificate.* FROM certificates WHERE certificate_id==$Certificate.certificate_id or certificate==$Certificate.certificate"
	updateCertificateStmt   = "UPDATE certificates SET issuer_id=$Certificate.issuer_id WHERE certificate_id==$Certificate.certificate_id or certificate==$Certificate.certificate"
	listCertificatesStmt    = "SELECT &Certificate.* FROM certificates"
	deleteCertificateStmt   = "DELETE FROM certificates WHERE certificate_id=$Certificate.certificate_id or certificate=$Certificate.certificate"

	getCertificateChainStmt = `WITH RECURSIVE cert_chain AS (
    -- Initial query: Start search from the end certificate
    SELECT certificate_id, certificate, issuer_id
    FROM certificates
    WHERE certificate_id = $Certificate.certificate_id or certificate = $Certificate.certificate

    UNION ALL

    -- Recursive Query: Move up the chain until issuer_id is 0 (root)
    SELECT certs.certificate_id, certs.certificate, certs.issuer_id
    FROM certificates certs
    JOIN cert_chain
      ON certs.certificate_id = cert_chain.issuer_id
)
SELECT &Certificate.* FROM cert_chain;`

	// // // // // // // // // // // // // //
	//  Certificate Authority SQL Strings  //
	// // // // // // // // // // // // // //
	createCertificateAuthorityStmt = "INSERT INTO certificate_authorities (crl, status, private_key_id, csr_id, certificate_id) VALUES ($CertificateAuthority.crl, $CertificateAuthority.status, $CertificateAuthority.private_key_id, $CertificateAuthority.csr_id, $CertificateAuthority.certificate_id)"
	getCertificateAuthorityStmt    = "SELECT &CertificateAuthority.* FROM certificate_authorities WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id or certificate_id==$CertificateAuthority.certificate_id"
	listCertificateAuthoritiesStmt = "SELECT &CertificateAuthority.* FROM certificate_authorities"
	updateCertificateAuthorityStmt = "UPDATE certificate_authorities SET crl=$CertificateAuthority.crl, status=$CertificateAuthority.status, certificate_id=$CertificateAuthority.certificate_id WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id"
	deleteCertificateAuthorityStmt = "DELETE FROM certificate_authorities WHERE certificate_authority_id=$CertificateAuthority.certificate_authority_id or csr_id=$CertificateAuthority.csr_id"

	listDenormalizedCertificateAuthoritiesStmt = `
WITH RECURSIVE cas_with_chain AS (
    SELECT
        cas.certificate_authority_id,
        cas.private_key_id,
		cas.csr_id,
        cas.status,
        cas.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        COALESCE(certs.certificate, '') AS chain
    FROM certificate_authorities cas
    LEFT JOIN certificates certs ON cas.certificate_id = certs.certificate_id

    UNION ALL

    SELECT
        cc.certificate_authority_id,
		cc.private_key_id,
		cc.csr_id,
        cc.status,
		cc.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        cc.chain || CHAR(10) || certs.certificate AS chain
    FROM cas_with_chain cc
    JOIN certificates certs ON certs.certificate_id = cc.issuer_id
)
	SELECT
		cc.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		cc.crl as &CertificateAuthorityDenormalized.crl,
		cc.status as &CertificateAuthorityDenormalized.status,
		cc.private_key_id AS &CertificateAuthorityDenormalized.private_key_id,
		cc.chain AS &CertificateAuthorityDenormalized.certificate_chain,
		csrs.csr AS &CertificateAuthorityDenormalized.csr
	FROM cas_with_chain cc
	LEFT JOIN certificate_requests csrs ON cc.csr_id = csrs.csr_id
	WHERE cc.chain = '' OR cc.issuer_id = 0`
	getDenormalizedCertificateAuthorityStmt = `
WITH RECURSIVE cas_with_chain AS (
    SELECT
        cas.certificate_authority_id,
        cas.private_key_id,
		cas.csr_id,
        cas.status,
        cas.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        COALESCE(certs.certificate, '') AS chain
    FROM certificate_authorities cas
    LEFT JOIN certificates certs ON cas.certificate_id = certs.certificate_id

    UNION ALL

    SELECT
        cc.certificate_authority_id,
		cc.private_key_id,
		cc.csr_id,
        cc.status,
		cc.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        cc.chain || CHAR(10) || certs.certificate AS chain
    FROM cas_with_chain cc
    JOIN certificates certs ON certs.certificate_id = cc.issuer_id
)
	SELECT
		cc.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		cc.crl as &CertificateAuthorityDenormalized.crl,
		cc.status as &CertificateAuthorityDenormalized.status,
		cc.private_key_id AS &CertificateAuthorityDenormalized.private_key_id,
		cc.chain AS &CertificateAuthorityDenormalized.certificate_chain,
		csrs.csr AS &CertificateAuthorityDenormalized.csr
	FROM cas_with_chain cc
	LEFT JOIN certificate_requests csrs ON cc.csr_id = csrs.csr_id
	WHERE cc.certificate_authority_id==$CertificateAuthorityDenormalized.certificate_authority_id
			or csrs.csr==$CertificateAuthorityDenormalized.csr
			and (issuer_id = 0 OR chain = '')`

	// // // // // // // // // //
	// Private Key SQL Strings //
	// // // // // // // // // //
	getPrivateKeyStmt    = "SELECT &PrivateKey.* FROM private_keys WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"
	createPrivateKeyStmt = "INSERT INTO private_keys (private_key) VALUES ($PrivateKey.private_key)"
	deletePrivateKeyStmt = "DELETE FROM private_keys WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"

	// // // // // // // // // //
	// Users Table SQL Strings //
	// // // // // // // // // //
	listUsersStmt   = "SELECT &User.* from users"
	getUserStmt     = "SELECT &User.* from users WHERE id==$User.id or username==$User.username"
	createUserStmt  = "INSERT INTO users (username, hashed_password, permissions) VALUES ($User.username, $User.hashed_password, $User.permissions)"
	updateUserStmt  = "UPDATE users SET hashed_password=$User.hashed_password WHERE id==$User.id or username==$User.username"
	deleteUserStmt  = "DELETE FROM users WHERE id==$User.id"
	getNumUsersStmt = "SELECT COUNT(*) AS &NumUsers.count FROM users"

	// // // // // // // // // //
	// Encryption Key SQL Strings //
	// // // // // // // // // //
	createEncryptionKeyStmt = "INSERT INTO encryption_keys (encryption_key_id, encryption_key) VALUES ($AES256GCMEncryptionKey.encryption_key_id, $AES256GCMEncryptionKey.encryption_key)"
	getEncryptionKeyStmt    = "SELECT &AES256GCMEncryptionKey.* FROM encryption_keys WHERE encryption_key_id=$AES256GCMEncryptionKey.encryption_key_id"
	deleteEncryptionKeyStmt = "DELETE FROM encryption_keys WHERE encryption_key_id=$AES256GCMEncryptionKey.encryption_key_id"

	// // // // // // // // // //
	// JWT Secret SQL Strings //
	// // // // // // // // // //
	createJWTSecretStmt = "INSERT INTO jwt_secret (id, encrypted_secret) VALUES ($JWTSecret.id, $JWTSecret.encrypted_secret)"
	getJWTSecretStmt    = "SELECT &JWTSecret.* FROM jwt_secret WHERE id=$JWTSecret.id"
	deleteJWTSecretStmt = "DELETE FROM jwt_secret WHERE id=$JWTSecret.id"
)

// Statements contains all prepared SQL statements used by the database
type Statements struct {
	// Certificate Request statements
	CreateCertificateRequest            *sqlair.Statement
	GetCertificateRequest               *sqlair.Statement
	GetCertificateRequestWithChain      *sqlair.Statement
	UpdateCertificateRequest            *sqlair.Statement
	ListCertificateRequests             *sqlair.Statement
	ListCertificateRequestsWithoutCAS   *sqlair.Statement
	ListCertificateRequestsWithChain    *sqlair.Statement
	ListCertificateRequestsWithoutChain *sqlair.Statement
	DeleteCertificateRequest            *sqlair.Statement

	// Certificate statements
	CreateCertificate   *sqlair.Statement
	GetCertificate      *sqlair.Statement
	ListCertificates    *sqlair.Statement
	DeleteCertificate   *sqlair.Statement
	GetCertificateChain *sqlair.Statement

	// Certificate Authority statements
	CreateCertificateAuthority             *sqlair.Statement
	GetCertificateAuthority                *sqlair.Statement
	GetDenormalizedCertificateAuthority    *sqlair.Statement
	UpdateCertificateAuthority             *sqlair.Statement
	ListCertificateAuthorities             *sqlair.Statement
	ListDenormalizedCertificateAuthorities *sqlair.Statement
	DeleteCertificateAuthority             *sqlair.Statement

	// Private Key statements
	CreatePrivateKey *sqlair.Statement
	GetPrivateKey    *sqlair.Statement
	DeletePrivateKey *sqlair.Statement

	// User statements
	CreateUser  *sqlair.Statement
	GetUser     *sqlair.Statement
	UpdateUser  *sqlair.Statement
	ListUsers   *sqlair.Statement
	DeleteUser  *sqlair.Statement
	GetNumUsers *sqlair.Statement

	// Encryption Key statements
	CreateEncryptionKey *sqlair.Statement
	GetEncryptionKey    *sqlair.Statement
	DeleteEncryptionKey *sqlair.Statement

	// JWT Secret statements
	CreateJWTSecret *sqlair.Statement
	GetJWTSecret    *sqlair.Statement
	DeleteJWTSecret *sqlair.Statement
}

// PrepareStatements prepares all SQL statements used by the database.
// This function runs once during initialization and prepares all SQL statements.
// It panics if any of the statements fail to prepare.
func PrepareStatements(db *sqlair.DB) *Statements {
	stmts := &Statements{}

	// Certificate Request statements
	stmts.CreateCertificateRequest = sqlair.MustPrepare(createCertificateRequestStmt, CertificateRequest{})
	stmts.GetCertificateRequest = sqlair.MustPrepare(getCertificateRequestStmt, CertificateRequest{})
	stmts.GetCertificateRequestWithChain = sqlair.MustPrepare(getCertificateRequestWithCertificateStmt, CertificateRequestWithChain{})
	stmts.UpdateCertificateRequest = sqlair.MustPrepare(updateCertificateRequestStmt, CertificateRequest{})
	stmts.ListCertificateRequests = sqlair.MustPrepare(listCertificateRequestsStmt, CertificateRequest{})
	stmts.ListCertificateRequestsWithoutCAS = sqlair.MustPrepare(listCertificateRequestsWithoutCASStmt, CertificateRequest{})
	stmts.ListCertificateRequestsWithChain = sqlair.MustPrepare(listCertificateRequestsWithCertificatesStmt, CertificateRequestWithChain{})
	stmts.ListCertificateRequestsWithoutChain = sqlair.MustPrepare(listCertificateRequestsWithCertificatesWithoutCASStmt, CertificateRequestWithChain{})
	stmts.DeleteCertificateRequest = sqlair.MustPrepare(deleteCertificateRequestStmt, CertificateRequest{})

	// Certificate statements
	stmts.CreateCertificate = sqlair.MustPrepare(createCertificateStmt, Certificate{})
	stmts.GetCertificate = sqlair.MustPrepare(getCertificateStmt, Certificate{})
	stmts.ListCertificates = sqlair.MustPrepare(listCertificatesStmt, Certificate{})
	stmts.DeleteCertificate = sqlair.MustPrepare(deleteCertificateStmt, Certificate{})
	stmts.GetCertificateChain = sqlair.MustPrepare(getCertificateChainStmt, Certificate{})

	// Certificate Authority statements
	stmts.CreateCertificateAuthority = sqlair.MustPrepare(createCertificateAuthorityStmt, CertificateAuthority{})
	stmts.GetCertificateAuthority = sqlair.MustPrepare(getCertificateAuthorityStmt, CertificateAuthority{})
	stmts.GetDenormalizedCertificateAuthority = sqlair.MustPrepare(getDenormalizedCertificateAuthorityStmt, CertificateAuthorityDenormalized{})
	stmts.UpdateCertificateAuthority = sqlair.MustPrepare(updateCertificateAuthorityStmt, CertificateAuthority{})
	stmts.ListCertificateAuthorities = sqlair.MustPrepare(listCertificateAuthoritiesStmt, CertificateAuthority{})
	stmts.ListDenormalizedCertificateAuthorities = sqlair.MustPrepare(listDenormalizedCertificateAuthoritiesStmt, CertificateAuthorityDenormalized{})
	stmts.DeleteCertificateAuthority = sqlair.MustPrepare(deleteCertificateAuthorityStmt, CertificateAuthority{})

	// Private Key statements
	stmts.CreatePrivateKey = sqlair.MustPrepare(createPrivateKeyStmt, PrivateKey{})
	stmts.GetPrivateKey = sqlair.MustPrepare(getPrivateKeyStmt, PrivateKey{})
	stmts.DeletePrivateKey = sqlair.MustPrepare(deletePrivateKeyStmt, PrivateKey{})

	// User statements
	stmts.CreateUser = sqlair.MustPrepare(createUserStmt, User{})
	stmts.GetUser = sqlair.MustPrepare(getUserStmt, User{})
	stmts.UpdateUser = sqlair.MustPrepare(updateUserStmt, User{})
	stmts.ListUsers = sqlair.MustPrepare(listUsersStmt, User{})
	stmts.DeleteUser = sqlair.MustPrepare(deleteUserStmt, User{})
	stmts.GetNumUsers = sqlair.MustPrepare(getNumUsersStmt, NumUsers{})

	// Encryption Key statements
	stmts.CreateEncryptionKey = sqlair.MustPrepare(createEncryptionKeyStmt, AES256GCMEncryptionKey{})
	stmts.GetEncryptionKey = sqlair.MustPrepare(getEncryptionKeyStmt, AES256GCMEncryptionKey{})
	stmts.DeleteEncryptionKey = sqlair.MustPrepare(deleteEncryptionKeyStmt, AES256GCMEncryptionKey{})

	// JWT Secret statements
	stmts.CreateJWTSecret = sqlair.MustPrepare(createJWTSecretStmt, JWTSecret{})
	stmts.GetJWTSecret = sqlair.MustPrepare(getJWTSecretStmt, JWTSecret{})
	stmts.DeleteJWTSecret = sqlair.MustPrepare(deleteJWTSecretStmt, JWTSecret{})

	return stmts
}
