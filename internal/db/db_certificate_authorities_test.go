package db_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestRootCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(RootCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" || ca.CertificateChain == "" {
		t.Fatalf("Certificate authority is not active or missing certificate")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CALegacy)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != db.CALegacy {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to legacy")
	}

	caRow, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CA to not be in the database: %s", err)
	}
	_, err = database.GetCertificateRequest(db.ByCSRID(caRow.CSRID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CSR to not be in the database: %s", err)
	}
	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(caRow.PrivateKeyID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected PrivateKey to not be in the database: %s", err)
	}
}

func TestIntermediateCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(IntermediateCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "pending" || ca.CertificateChain != "" {
		t.Fatalf("Certificate authority is not pending or has a certificate")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID), IntermediateCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" || ca.CertificateChain != IntermediateCACertificate+"\n"+RootCACertificate {
		t.Fatalf("Certificate authority is not active or has a certificate")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CALegacy)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "legacy" {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to legacy")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CAActive)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" {
		t.Fatalf("Certificate authority status is not active")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to Active")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
}

func TestCertificateAuthorityFails(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	_, err = database.CreateCertificateAuthority("", "", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "nope", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", RootCAPrivateKey, RootCACRL, "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("", RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "", RootCACRL, RootCACertificate+"\n"+RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "nope", RootCACRL, RootCACertificate+"\n"+RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, "", RootCACertificate+"\n"+RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}

	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(0), RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(10), RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(1), "")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(1), "no")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(0), "Legacy")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(10), "Legacy")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(1), "No")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityCSRID(19))
	if err == nil {
		t.Fatalf("Should have failed to delete certificate authority")
	}
}

func TestSelfSignedCertificateList(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csrs, err := database.ListCertificateRequestWithCertificates()
	if err != nil {
		t.Fatalf("Couldn't list certificates: %s", err)
	}
	if len(csrs) != 1 {
		t.Fatalf("%d certificates found when only 1 should be available", len(csrs))
	}
	if csrs[0].CertificateChain == "" {
		t.Fatalf("certificate should be available for CSR")
	}
}

func TestSigningCSRsFromSelfSignedCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	csrID, err := database.CreateCertificateRequest(AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign CSR: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
}

func TestSigningCSRsFromIntermediateCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, IntermediateCACRL, IntermediateCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected signed certificate chain to be 3 certificates long.")
	}
}

func TestSigningCSRFromUnsignedIntermediateCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "example.com")
	if err == nil {
		t.Fatalf("Expected signing to fail: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain != "" {
		t.Fatalf("Certificate should not have been signed.")
	}
}

func TestSigningIntermediateCAByRootCA(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	rootCAID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	intermediateCAID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRPEM(IntermediateCACSR), db.ByCertificateAuthorityDenormalizedID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	cas, err := database.ListDenormalizedCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if strings.Count(cas[0].CertificateChain, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("Expected root ca certificate chain to be 1 certificates long.")
	}
	if strings.Count(cas[1].CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected intermediate ca certificate chain to be 2 certificates long.")
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(intermediateCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected end certificate chain to be 3 certificates long.")
	}

	csrID, err = database.CreateCertificateRequest(StrawberryCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
}

func TestCertificateRevocationListsEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	// The root CA has a valid CRL with no entries.
	rootCAID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	rootCA, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err := db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}

	// The intermediate CA has no CRL.
	intermediateCAID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	intermediateCA, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL != "" {
		t.Fatalf("CRL available for a CA without a certificate")
	}

	// The signed intermediate CA has a valid and empty CRL,
	// and its certificate has a CRLDistributionPoint extension that points to the root CA's CRL.
	err = database.SignCertificateRequest(db.ByCSRPEM(IntermediateCACSR), db.ByCertificateAuthorityDenormalizedID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL == "" {
		t.Fatalf("CRL not available for a CA with a certificate")
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}
	certs, err := db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The signed CSR has a CRLDistributionPoint extension that points to the Intermediate CA's CRL with the correct hostname.
	csrID, err := database.CreateCertificateRequest(AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(intermediateCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/2/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/2/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the intermediate CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	AppleCertSerial := certs[0].SerialNumber.String()
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != AppleCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", AppleCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The signed certificate has a CRLDistributionPoint extension that points to the root CA's CRL with the correct hostname.
	csrID, err = database.CreateCertificateRequest(StrawberryCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	StrawberryCertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", StrawberryCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The revoked intermediate CA's certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRPEM(intermediateCA.CSRPEM))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	certs, err = db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	IntermediateCACertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL should have 2 entries, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
	if crl.RevokedCertificateEntries[1].SerialNumber.String() != IntermediateCACertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
}
