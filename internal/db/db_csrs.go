package db

import "fmt"

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequests() ([]CertificateRequest, error) {
	return ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequests)
}

// ListCertificateRequestsWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestsWithoutCAS() ([]CertificateRequest, error) {
	return ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequestsWithoutCAS)
}

// ListCertificateRequestsWithCertificates gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestsWithCertificates() ([]CertificateRequestWithChain, error) {
	return ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithChain)
}

// ListCertificateRequestsWithCertificatesWithoutCAS gets every CertificateRequest entry in the table.
// Supports no filter, or filter with OwnerID
func (db *Database) ListCertificateRequestsWithCertificatesWithoutCAS(filter *CSRFilter) ([]CertificateRequestWithChain, error) {
	if filter == nil {
		return ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithoutChain)
	}
	if filter.ID != nil {
		panic(fmt.Errorf("%w: ID field not supported when listing CertificateRequests", ErrInvalidFilter))
	}
	if filter.PEM != nil {
		panic(fmt.Errorf("%w: PEM field not supported when listing CertificateRequests", ErrInvalidFilter))
	}
	csrRow := filter.AsCertificateRequestWithChain()
	return ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithoutChainByOwnerID, *csrRow)
}

// GetCertificateRequestByID gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequest(filter *CSRFilter) (*CertificateRequest, error) {
	csrRow := filter.AsCertificateRequest()
	if filter.OwnerID != nil {
		panic(fmt.Errorf("%w: Owner ID field not supported when getting a CertificateRequest", ErrInvalidFilter))
	}
	return GetOneEntity[CertificateRequest](db, db.stmts.GetCertificateRequest, *csrRow)
}

// GetCertificateRequestAndChain gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequestAndChain(filter *CSRFilter) (*CertificateRequestWithChain, error) {
	csrRow := filter.AsCertificateRequestWithChain()
	if csrRow.OwnerID != 0 {
		panic(fmt.Errorf("%w: Owner ID field not supported when getting a CertificateRequest", ErrInvalidFilter))
	}
	return GetOneEntity[CertificateRequestWithChain](db, db.stmts.GetCertificateRequestWithChain, *csrRow)
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCertificateRequest(csr string, ownerID int64) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, err
	}
	row := CertificateRequest{
		CSR:     csr,
		OwnerID: ownerID,
	}
	return CreateEntity(db, db.stmts.CreateCertificateRequest, row)
}

// RejectCertificateRequest updates input CSR's row by unassigning the certificate ID and moving the row status to "Rejected".
func (db *Database) RejectCertificateRequest(filter *CSRFilter) error {
	row := filter.AsCertificateRequest()

	row.CertificateID = 0
	row.Status = "rejected"

	return UpdateEntity(db, db.stmts.UpdateCertificateRequest, row)
}

// DeleteCertificateRequest removes a CSR from the database.
func (db *Database) DeleteCertificateRequest(filter *CSRFilter) error {
	csrRow := filter.AsCertificateRequest()
	return DeleteEntity(db, db.stmts.DeleteCertificateRequest, csrRow)
}
