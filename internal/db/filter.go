package db

type CertificateFilter struct {
	ID  *int
	PEM *string
}

func ByCertificateID(id int) CertificateFilter {
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
