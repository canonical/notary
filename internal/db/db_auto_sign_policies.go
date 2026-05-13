package db

// CreateAutoSignPolicy creates an auto-sign policy for a certificate authority.
func (db *DatabaseRepository) CreateAutoSignPolicy(policy AutoSignPolicy) (int64, error) {
	return CreateEntity(db, db.stmts.CreateAutoSignPolicy, policy)
}

// GetAutoSignPolicy gets the auto-sign policy for a given certificate authority ID.
func (db *DatabaseRepository) GetAutoSignPolicy(caID int64) (*AutoSignPolicy, error) {
	row := AutoSignPolicy{CertificateAuthorityID: caID}
	return GetOneEntity[AutoSignPolicy](db, db.stmts.GetAutoSignPolicy, row)
}

// GetAutoSignPolicyByPolicyID gets the auto-sign policy by its own policy ID.
func (db *DatabaseRepository) GetAutoSignPolicyByPolicyID(policyID int64) (*AutoSignPolicy, error) {
	row := AutoSignPolicy{PolicyID: policyID}
	return GetOneEntity[AutoSignPolicy](db, db.stmts.GetAutoSignPolicyByPolicyID, row)
}

// UpdateAutoSignPolicy updates the auto-sign policy for a certificate authority.
func (db *DatabaseRepository) UpdateAutoSignPolicy(policy AutoSignPolicy) error {
	return UpdateEntity(db, db.stmts.UpdateAutoSignPolicy, &policy)
}

// DeleteAutoSignPolicy deletes the auto-sign policy for a certificate authority.
func (db *DatabaseRepository) DeleteAutoSignPolicy(caID int64) error {
	row := AutoSignPolicy{CertificateAuthorityID: caID}
	return DeleteEntity(db, db.stmts.DeleteAutoSignPolicy, &row)
}

// ListActiveAutoSignPolicies returns all enabled auto-sign policies.
func (db *DatabaseRepository) ListActiveAutoSignPolicies() ([]AutoSignPolicy, error) {
	return ListEntities[AutoSignPolicy](db, db.stmts.ListActiveAutoSignPolicies)
}

// ListOutstandingCSRsExcludingCAs returns certificate requests with status 'Outstanding'
// that do not belong to certificate authorities.
func (db *DatabaseRepository) ListOutstandingCSRsExcludingCAs() ([]CertificateRequest, error) {
	return ListEntities[CertificateRequest](db, db.stmts.ListOutstandingCSRsExcludingCAS)
}