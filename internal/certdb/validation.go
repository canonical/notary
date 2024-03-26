package certdb

func ValidateCertificateRequest(csr string) error {
	return nil
}

func ValidateCertificate(cert string, csr string) error {

	if csr == "" {
		return nil
	}
	return nil
}
