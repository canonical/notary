package db

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequests() ([]CertificateRequest, error) {
	return ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequests)
}

// ListCertificateRequestsWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestsWithoutCAS() ([]CertificateRequest, error) {
	return ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequestsWithoutCAS)
}

// ListCertificateRequestWithCertificates gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificates() ([]CertificateRequestWithChain, error) {
	return ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithChain)
}

// ListCertificateRequestWithCertificatesWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificatesWithoutCAS() ([]CertificateRequestWithChain, error) {
	return ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithoutChain)
}

// GetCertificateRequestByID gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequest(filter CSRFilter) (*CertificateRequest, error) {
	csrRow := filter.AsCertificateRequest()
	return GetOneEntity(db, db.stmts.GetCertificateRequest, *csrRow)
}

// GetCertificateRequestAndChain gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequestAndChain(filter CSRFilter) (*CertificateRequestWithChain, error) {
	csrRow := filter.AsCertificateRequestWithChain()
	return GetOneEntity(db, db.stmts.GetCertificateRequestWithChain, *csrRow)
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCertificateRequest(csr string) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, err
	}
	row := CertificateRequest{
		CSR: csr,
	}
	return CreateEntity(db, db.stmts.CreateCertificateRequest, row)
}

// RejectCertificateRequest updates input CSR's row by unassigning the certificate ID and moving the row status to "Rejected".
func (db *Database) RejectCertificateRequest(filter CSRFilter) error {
	row := filter.AsCertificateRequest()

	row.CertificateID = 0
	row.Status = "Rejected"

	return UpdateEntity(db, db.stmts.UpdateCertificateRequest, row)
}

// DeleteCertificateRequest removes a CSR from the database.
func (db *Database) DeleteCertificateRequest(filter CSRFilter) error {
	csrRow := filter.AsCertificateRequest()
	return DeleteEntity(db, db.stmts.DeleteCertificateRequest, csrRow)
}
