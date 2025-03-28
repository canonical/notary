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
	ID  *int64
	PEM *string
}

func ByCSRID(id int64) CSRFilter {
	return CSRFilter{ID: &id}
}

func ByCSRPEM(pem string) CSRFilter {
	return CSRFilter{PEM: &pem}
}

type UserFilter struct {
	ID       *int64
	Username *string
}

func ByUserID(id int64) UserFilter {
	return UserFilter{ID: &id}
}

func ByUsername(username string) UserFilter {
	return UserFilter{Username: &username}
}

type PrivateKeyFilter struct {
	ID  *int64
	PEM *string
}

func ByPrivateKeyID(id int64) PrivateKeyFilter {
	return PrivateKeyFilter{ID: &id}
}

func ByPrivateKeyPEM(pem string) PrivateKeyFilter {
	return PrivateKeyFilter{PEM: &pem}
}

type CertificateAuthorityFilter struct {
	ID            *int64
	CSRID         *int64
	CSRPEM        *string
	CertificateID *int64
}

func ByCertificateAuthorityID(id int64) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{ID: &id}
}

func ByCertificateAuthorityCSRID(id int64) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{CSRID: &id}
}

func ByCertificateAuthorityCertificateID(id int64) CertificateAuthorityFilter {
	return CertificateAuthorityFilter{CertificateID: &id}
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
	case filter.CertificateID != nil:
		CARow = CertificateAuthority{CertificateID: *filter.CertificateID}
	default:
		return &CARow, fmt.Errorf("empty filter: only CA ID, CSR ID or Certificate ID is supported but none was provided")
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
