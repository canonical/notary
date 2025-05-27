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

func (filter *CertificateFilter) AsCertificate() *Certificate {
	var certRow Certificate

	switch {
	case filter.ID != nil:
		certRow = Certificate{CertificateID: *filter.ID}
	case filter.PEM != nil:
		certRow = Certificate{CertificatePEM: *filter.PEM}
	default:
		panic(fmt.Errorf("%w: empty filter: only certificate ID or PEM is supported but none was provided", ErrInvalidFilter))
	}
	return &certRow
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

func (filter *CSRFilter) AsCertificateRequest() *CertificateRequest {
	var csrRow CertificateRequest

	switch {
	case filter.ID != nil:
		csrRow = CertificateRequest{CSR_ID: *filter.ID}
	case filter.PEM != nil:
		csrRow = CertificateRequest{CSR: *filter.PEM}
	default:
		panic(fmt.Errorf("%w: only CSR ID or PEM is supported but none was provided", ErrInvalidFilter))
	}
	return &csrRow
}

func (filter *CSRFilter) AsCertificateRequestWithChain() *CertificateRequestWithChain {
	var csrRow CertificateRequestWithChain

	switch {
	case filter.ID != nil:
		csrRow = CertificateRequestWithChain{CSR_ID: *filter.ID}
	case filter.PEM != nil:
		csrRow = CertificateRequestWithChain{CSR: *filter.PEM}
	default:
		panic(fmt.Errorf("%w: only CSR ID or PEM is supported but none was provided", ErrInvalidFilter))
	}
	return &csrRow
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

func (filter *UserFilter) AsUser() *User {
	var userRow User

	switch {
	case filter.ID != nil:
		userRow = User{ID: *filter.ID}
	case filter.Username != nil:
		userRow = User{Username: *filter.Username}
	default:
		panic(fmt.Errorf("%w: only user ID or username is supported but none was provided", ErrInvalidFilter))
	}
	return &userRow
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

func (filter *PrivateKeyFilter) AsPrivateKey() *PrivateKey {
	var pkRow PrivateKey

	switch {
	case filter.ID != nil:
		pkRow = PrivateKey{PrivateKeyID: *filter.ID}
	case filter.PEM != nil:
		pkRow = PrivateKey{PrivateKeyPEM: *filter.PEM}
	default:
		panic(fmt.Errorf("%w: only private key ID or PEM is supported but none was provided", ErrInvalidFilter))
	}
	return &pkRow
}

type CertificateAuthorityFilter struct {
	ID    *int64
	CSRID *int64
	// CSRPEM        *string
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

func (filter *CertificateAuthorityFilter) AsCertificateAuthority() *CertificateAuthority {
	var CARow CertificateAuthority

	switch {
	case filter.ID != nil:
		CARow = CertificateAuthority{CertificateAuthorityID: *filter.ID}
	case filter.CSRID != nil:
		CARow = CertificateAuthority{CSRID: *filter.CSRID}
	case filter.CertificateID != nil:
		CARow = CertificateAuthority{CertificateID: *filter.CertificateID}
	default:
		panic(fmt.Errorf("%w: only CA ID, CSR ID or Certificate ID is supported but none was provided", ErrInvalidFilter))
	}
	return &CARow
}

type CertificateAuthorityDenormalizedFilter struct {
	ID     *int64
	CSRPEM *string
}

func ByCertificateAuthorityDenormalizedCSRPEM(pem string) CertificateAuthorityDenormalizedFilter {
	return CertificateAuthorityDenormalizedFilter{CSRPEM: &pem}
}

func ByCertificateAuthorityDenormalizedID(id int64) CertificateAuthorityDenormalizedFilter {
	return CertificateAuthorityDenormalizedFilter{ID: &id}
}

func (filter *CertificateAuthorityDenormalizedFilter) AsCertificateAuthorityDenormalized() *CertificateAuthorityDenormalized {
	var CADenormalizedRow CertificateAuthorityDenormalized

	switch {
	case filter.ID != nil:
		CADenormalizedRow = CertificateAuthorityDenormalized{CertificateAuthorityID: *filter.ID}
	case filter.CSRPEM != nil:
		CADenormalizedRow = CertificateAuthorityDenormalized{CSRPEM: *filter.CSRPEM}
	default:
		panic(fmt.Errorf("%w: only CA ID or CSR PEM is supported but none was provided", ErrInvalidFilter))
	}
	return &CADenormalizedRow
}
