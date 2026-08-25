package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PrepareJoin generates the joining node's key pair and returns a PEM encoded
// certificate signing request to present to an existing member.
//
// The private key never leaves this node: only the CSR is sent. The returned CSR
// is not usable on its own — an existing member will only sign it in exchange
// for a valid join token.
func PrepareJoin(stateDir string, address string) ([]byte, error) {
	if address == "" {
		return nil, errors.New("cluster address is required")
	}

	dir := PKIDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create cluster PKI directory: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster node key: %w", err)
	}

	keyPEM, err := encodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, nodeKeyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write cluster node key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: address},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster join request: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// CompleteJoin stores the cluster credentials an existing member issued for this
// node: its signed certificate, the cluster CA certificate needed to verify
// peers, and the CA key that lets it admit future joins in turn. After this the
// node's PKI directory is indistinguishable from a bootstrapped one.
//
// The CA key is deliberately given to every member. A member already replicates
// the whole of Notary's database, so withholding it buys no confidentiality,
// while keeping it on the bootstrapping node alone would make that node a single
// point of failure for every future join.
func CompleteJoin(stateDir string, certPEM, caCertPEM, caKeyPEM []byte) error {
	dir := PKIDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create cluster PKI directory: %w", err)
	}

	if _, err := parseCertificatePEM(certPEM); err != nil {
		return fmt.Errorf("signed node certificate is unusable: %w", err)
	}
	if _, err := parseCertificatePEM(caCertPEM); err != nil {
		return fmt.Errorf("cluster CA certificate is unusable: %w", err)
	}
	if _, err := parseCAKey(caKeyPEM); err != nil {
		return fmt.Errorf("cluster CA key is unusable: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, caCertFile), caCertPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write cluster CA certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), caKeyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write cluster CA key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write cluster node certificate: %w", err)
	}

	return nil
}

// ValidateJoinCSR reports whether csrPEM is a well formed certificate signing
// request. The join handler calls it before redeeming the caller's token, so a
// malformed request cannot burn a single-use token.
func ValidateJoinCSR(csrPEM []byte) error {
	_, err := parseCertificateRequestPEM(csrPEM)
	return err
}

// SignJoinRequest issues a cluster node certificate to a joining member. It
// returns the signed certificate, the cluster CA certificate the new member
// needs to verify its peers, and the CA key it needs to admit joins itself.
//
// Only the public key is taken from the CSR. Every other field — subject, SANs,
// key usages, validity — is set by this node, so a joining node cannot influence
// what its certificate authorizes by crafting the request. address is supplied
// by the caller alongside the CSR and is what the certificate is bound to.
func SignJoinRequest(stateDir string, csrPEM []byte, address string) (certPEM, caCertPEM, caKeyPEM []byte, err error) {
	if address == "" {
		return nil, nil, nil, errors.New("cluster address is required")
	}

	csr, err := parseCertificateRequestPEM(csrPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	dir := PKIDir(stateDir)
	caCertPEM, err = os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read cluster CA certificate: %w", err)
	}
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	var caKey *ecdsa.PrivateKey
	caKeyPEM, caKey, err = loadCAKey(dir)
	if err != nil {
		return nil, nil, nil, err
	}

	der, err := signNodeCertificate(caCert, caKey, csr.PublicKey, address)
	if err != nil {
		return nil, nil, nil, err
	}

	return encodeCertificate(der), caCertPEM, caKeyPEM, nil
}

// loadCAKey reads the cluster CA private key, returning it both as stored and
// parsed. Every member holds it, so every member can admit a new one.
func loadCAKey(dir string) ([]byte, *ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cluster CA key: %w", err)
	}

	key, err := parseCAKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	return keyPEM, key, nil
}

func parseCAKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("cluster CA key is not valid PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster CA key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cluster CA key is %T, want an ECDSA key", parsed)
	}

	return key, nil
}

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("certificate is not valid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func parseCertificateRequestPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("certificate request is not valid PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}
	// Proves the requester holds the private key for the public key it is asking
	// to have certified.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature is invalid: %w", err)
	}

	return csr, nil
}
