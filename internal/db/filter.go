package db

import "fmt"

type CertificateFilter struct {
	ID  *int64
	PEM *string
}

func ByCertificateID(id int64) CertificateFilter {
	return CertificateFilter{ID: &id}
}

func ByCertificatePEM(pem string) CertificateFilter {
	return CertificateFilter{PEM: &pem}
}

type CSRFilter struct {
	ID  *int
	PEM *string
}

func ByCSRID(id int) CSRFilter {
	return CSRFilter{ID: &id}
}

func ByCSRPEM(pem string) CSRFilter {
	return CSRFilter{PEM: &pem}
}

type UserFilter struct {
	ID       *int
	Username *string
}

func ByUserID(id int) UserFilter {
	return UserFilter{ID: &id}
}

func ByUsername(username string) UserFilter {
	return UserFilter{Username: &username}
}

type PrivateKeyFilter struct {
	ID  *int
	PEM *string
}

func ByPrivateKeyID(id int) PrivateKeyFilter {
	return PrivateKeyFilter{ID: &id}
}

func ByPrivateKeyPEM(pem string) PrivateKeyFilter {
	return PrivateKeyFilter{PEM: &pem}
}

type CertificateAuthorityFilter struct {
	ID     *int
	CSRID  *int
	CSRPEM *string
}

func ByCertificateAuthorityID(id int) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{ID: &id}
}

func ByCertificateAuthorityCSRID(id int) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{CSRID: &id}
}

func ByCertificateAuthorityCSRPEM(pem string) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{CSRPEM: &pem}
}

func (filter *CertificateAuthorityFilter) AsCertificateAuthority() (*CertificateAuthority, error) {
	var CARow CertificateAuthority

	switch {
	case filter.ID != nil:
		CARow = CertificateAuthority{CertificateAuthorityID: *filter.ID}
	case filter.CSRID != nil:
		CARow = CertificateAuthority{CSRID: *filter.CSRID}
	default:
		return &CARow, fmt.Errorf("empty filter: only CA ID or CSR ID is supported but none was provided")
	}
	return &CARow, nil
}
func (filter *CertificateAuthorityFilter) AsCertificateAuthorityDenormalized() (*CertificateAuthorityDenormalized, error) {
	var CADenormalizedRow CertificateAuthorityDenormalized

	switch {
	case filter.ID != nil:
		CADenormalizedRow = CertificateAuthorityDenormalized{CertificateAuthorityID: *filter.ID}
	case filter.CSRPEM != nil:
		CADenormalizedRow = CertificateAuthorityDenormalized{CSRPEM: *filter.CSRPEM}
	default:
		return &CADenormalizedRow, fmt.Errorf("empty filter: only CA ID or CSR PEM is supported but none was provided")
	}
	return &CADenormalizedRow, nil
}
