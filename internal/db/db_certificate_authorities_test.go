package db_test

import (
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
)

const (
	// CommonName:          "Testing Self Signed CA",
	// CountryName:         "Testing Country",
	// StateOrLocalityName: "Testing State",
	// LocalityName:        "Testing Locality",
	// OrganizationName:    "Testing Organization",
	// OrganizationalUnit:  "Testing OU",
	// SANsDNS:             "testing.dns",
	selfSignedCACertificateRequest = `-----BEGIN CERTIFICATE REQUEST-----
MIIFETCCAvkCAQAwgaIxGDAWBgNVBAYTD1Rlc3RpbmcgQ291bnRyeTEWMBQGA1UE
CBMNVGVzdGluZyBTdGF0ZTEZMBcGA1UEBxMQVGVzdGluZyBMb2NhbGl0eTEdMBsG
A1UEChMUVGVzdGluZyBPcmdhbml6YXRpb24xEzARBgNVBAsTClRlc3RpbmcgT1Ux
HzAdBgNVBAMTFlRlc3RpbmcgU2VsZiBTaWduZWQgQ0EwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCrPCyGrXjPTWh/9MI76bVdb2TxEuItx7ZpUQrVWO5Y
BHenwfg6HXpOQVSFedfJj7qBaz4MopqJfkl6TPUA8oZLSAY4xsZZB+N1I/Xoke8D
zTOLpgzFXy9zymIJ0fMrbYX3e1OxXMkEvUClAr5OaFLZaM8oz205spp+jq42Ad3v
x4QdWf5AGTC8PwekKcDvctptHLKUnU0Lyn58dPz63QeM1Vk2wRk7NYVknvnmhJl1
X3j0q5hWdkN/5mqaa7lKDAj2WX3SEArYiaTuESbq37dWJF0TwxuYtEUHKQuGBZli
cnbDMb3+efgfKYmZK3wHM+L5E99tc4IG90JF70xUO0LAeEa6Q4zfIX+x9B7rkQEB
METY+xElYYih5pouMrmtPoK9Cdztgpdq/wY5CgCf6jyoq6+x/pci2VEAtZ/DBaZ0
R9shfep6X4/aE0XiJSjK3NAogGIxS30gA/BblmHuNUruGbVK/3g/pQiSpt0yChr/
CX1T68U6LjOCMZTyjcyPJcvvXq1oL/k7ygYHO00M2dzgHg/jr4NX83IaqnkT8NN9
mm+yVGkpSM6aLyDwloMjKmXSbb/zbl3T6gbmc+scJAvBdtVYHZSnB8xwXom2HRJs
gzsEb/U2co3k5zMiSGg3aKWxEUU01r5kQ8jhobNv0nkd/h3rcJPNW0HfxJ2eHusz
FQIDAQABoCkwJwYJKoZIhvcNAQkOMRowGDAWBgNVHREEDzANggt0ZXN0aW5nLmRu
czANBgkqhkiG9w0BAQsFAAOCAgEAMK+zjyR+TjiUMfkPbdp7I/vKVuM5kLZlXaiZ
4m0o2eZq4NiYGyd8tQ89z69KDSoTEgqEq9oYv2CRXX/LuTLVV49TfWHosuKEW2/S
i+kEIohJGRbkZHi6hzyvFIEupvLEh8nqR+bUgiSY3hcjpGSx8SaFVfTmKGIjnQKf
rB5Cdwvy34s4zMMIIVskDJ9OKju0+TlwtbqmEUHwhNu7YvO/IOzLh3u752plNg4y
GxweZ81Zmba1vg+cpa9K6zt/d4qwbl87AnINn9LkNaa26MBmL7bjLaAfWZ3IrHLd
T174+z6F02RGLSIk12cqS25XxNGI5SZsihlOiHpPhPwlo2+qE9iN/1K61/gyV9po
DZmBRt0UJUoAy8pFhWS9ACiYSv/UPvcGm23sgFU0uBbdeIyzkqd325VtjMJsxqUB
El25Bi4L14/N6mbX4+aN2tHvcGtROHrVw61FdZEtl7DIswAxwivP5R3FHGm8mS4o
qASYLmyowC+bu0kQ80Y4tjTBQpUU8fyYlwfgyolhvkXawyh01zlSrlmE/RxWJ7G4
QEx5L8Oul3oTD7rCNhUwVgN4V1jIsqCi7Sj8sGC992E11h1hRZqHOexDzXSEjGhX
u79Bb1vhcmzR1NEn6HXCQ2qbO5BMteQ2Tyb9xU7oXJiMEbChsKElcwXl0ykHWEVE
am89s9g=
-----END CERTIFICATE REQUEST-----`
	selfSignedCACertificatePK = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	selfSignedCACertificate = `-----BEGIN CERTIFICATE-----
MIIGHzCCBAegAwIBAgIIGCEGnc3aBTkwDQYJKoZIhvcNAQELBQAwgaIxGDAWBgNV
BAYTD1Rlc3RpbmcgQ291bnRyeTEWMBQGA1UECBMNVGVzdGluZyBTdGF0ZTEZMBcG
A1UEBxMQVGVzdGluZyBMb2NhbGl0eTEdMBsGA1UEChMUVGVzdGluZyBPcmdhbml6
YXRpb24xEzARBgNVBAsTClRlc3RpbmcgT1UxHzAdBgNVBAMTFlRlc3RpbmcgU2Vs
ZiBTaWduZWQgQ0EwHhcNMjUwMjA0MTQxMDA1WhcNMzUwMjA0MTQxMDA1WjCBojEY
MBYGA1UEBhMPVGVzdGluZyBDb3VudHJ5MRYwFAYDVQQIEw1UZXN0aW5nIFN0YXRl
MRkwFwYDVQQHExBUZXN0aW5nIExvY2FsaXR5MR0wGwYDVQQKExRUZXN0aW5nIE9y
Z2FuaXphdGlvbjETMBEGA1UECxMKVGVzdGluZyBPVTEfMB0GA1UEAxMWVGVzdGlu
ZyBTZWxmIFNpZ25lZCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AKs8LIateM9NaH/0wjvptV1vZPES4i3HtmlRCtVY7lgEd6fB+Dodek5BVIV518mP
uoFrPgyimol+SXpM9QDyhktIBjjGxlkH43Uj9eiR7wPNM4umDMVfL3PKYgnR8ytt
hfd7U7FcyQS9QKUCvk5oUtlozyjPbTmymn6OrjYB3e/HhB1Z/kAZMLw/B6QpwO9y
2m0cspSdTQvKfnx0/PrdB4zVWTbBGTs1hWSe+eaEmXVfePSrmFZ2Q3/mappruUoM
CPZZfdIQCtiJpO4RJurft1YkXRPDG5i0RQcpC4YFmWJydsMxvf55+B8piZkrfAcz
4vkT321zggb3QkXvTFQ7QsB4RrpDjN8hf7H0HuuRAQEwRNj7ESVhiKHmmi4yua0+
gr0J3O2Cl2r/BjkKAJ/qPKirr7H+lyLZUQC1n8MFpnRH2yF96npfj9oTReIlKMrc
0CiAYjFLfSAD8FuWYe41Su4ZtUr/eD+lCJKm3TIKGv8JfVPrxTouM4IxlPKNzI8l
y+9erWgv+TvKBgc7TQzZ3OAeD+Ovg1fzchqqeRPw032ab7JUaSlIzpovIPCWgyMq
ZdJtv/NuXdPqBuZz6xwkC8F21VgdlKcHzHBeibYdEmyDOwRv9TZyjeTnMyJIaDdo
pbERRTTWvmRDyOGhs2/SeR3+Hetwk81bQd/EnZ4e6zMVAgMBAAGjVzBVMA4GA1Ud
DwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSbXLqZuUAgHvDfdpdDNDggifOgETANBgkqhkiG9w0BAQsFAAOC
AgEAKlIcm2sMw6a9PoNFUXLHkGo46Lao1uRJ51tNGBXasbkznb3N8pr0vhVWQk7W
QM8nd8t8yvaQ7ELo/SapBkjTyu8SwPRVbnXjl1Wke3A34VMusjhIGPNsjgI6zq8i
rmzzFSNGb+T0AngOc6dMC9N2pAWFHnmzty7Oi39R/jhOmD38wWCMyS1Lui5tXIMJ
hk/PnVEMF3Rx4rV8FBZh3IJE5O2hB4OCTQVh3w2kOI5+YRWTJm223WfHz7XHR2Ny
E6yjQhPeglxspeNufhD1H8B49/XuIsHqOBrIPUxztyuBJwXz0KuFitbLrRHLaz2T
9Ox0i6jEB5f4RU1AiwpM6KE7bFkXmWIYeOykQq7Rj0qGdo50MABGAErIIXpcRzvn
0r3y1PCvjntdrc9IG8b0bQhVss5Irr9+5wdn90lnKAi2wASmRxbYNVuIi6BpXJvk
lFukciXd3eW7qZrgUFzS2nBwXv7wlT6e7pfGChSrE+dlh6QBHkDlHU2FdwdAc8BX
GbaLCYgW2R7/cgFG25APKkLxVzuIVYCQzIc94vyTqdhEhdQfvDTnnE/Nj//lVJBp
vpdEAlIxCc8EPphBf2okYk9nbda/3fTIBlYhXo3jGw/luYY+rv3YBMzPJ9KXkfxH
nCSo5Rj3yTrtNYFLnu+iLCvMb5PcJXE55Pu5OYGktHnvMgc=
-----END CERTIFICATE-----`
)

func TestRootCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %d", err)
	}
	defer database.Close()

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %d", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	err = database.CreateCertificateAuthority(selfSignedCACertificateRequest, selfSignedCACertificatePK, selfSignedCACertificate+"\n"+selfSignedCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %d", err)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %d", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(selfSignedCACertificateRequest)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %d", err)
	}
	if ca.Status != "Active" || ca.CertificatePEM == "" {
		t.Fatalf("Certificate authority is not active or missing certificate")
	}

	err = database.UpdateCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), "", "Legacy")
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %d", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %d", err)
	}
	if ca.Status != "Legacy" {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificatePEM == "" {
		t.Fatalf("Certificate should not have been removed when updating status to legacy")
	}

	err = database.UpdateCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), "", "Active")
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %d", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %d", err)
	}
	if ca.Status != "Active" {
		t.Fatalf("Certificate authority status is not active")
	}
	if ca.CertificatePEM == "" {
		t.Fatalf("Certificate should not have been removed when updating status to Active")
	}

	// TODO: Sign a couple CSRs and then revoke them all
	// TODO: Sign the same CSRs again, have an extra one that wasn't signed
	// TODO: Renew self and then check if all of the CSR's were revoked. Check if the one that wasn't signed by this CA was NOT revoked.

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %d", err)
	}

}

func TestIntermediateCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %d", err)
	}
	defer database.Close()

	// Create a CA
	// It should automatically go to pending and have a csr with no certificate.
	// Sign it with a different self signed CA
	// Make legacy should make it legacy
	// Make active should make it active
	// TODO: Sign a couple CSRs and then revoke them all
	// TODO: Sign the same CSRs again, have an extra one that wasn't signed
	// TODO: Renew self and then check if all of the CSR's were revoked. Check if the one that wasn't signed by this CA was NOT revoked.
}

func TestMultipleCertificateAuthoritiesEndToEnd(t *testing.T) {
	// TODO
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %d", err)
	}
	defer database.Close()

	// Create a self signed CA
	// Create an intermediate CA
	// Sign intermediate CA with the self signed CA
	// Sign some CSRs with intermediate CA
	// Renew self signed CA
	// check if intermediate CA was revoked (shoud it just be made legacy or should it also be revoked?)
	// check if certs signed by intermediate ca's were revoked (is this how it should be?)

}

func TestCertificateAuthorityFails(t *testing.T) {

}
