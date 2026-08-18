package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// clusterSANDNS is the DNS name carried by every node certificate in the
	// cluster, and it must be the *first* DNS SAN on each of them.
	//
	// go-dqlite's app.SimpleDialTLSConfig derives the TLS ServerName it presents
	// when dialing peers from the first DNS SAN of the node's own certificate
	// (app/tls.go), so every member has to agree on that name or no member can
	// verify any other. It is a cluster-internal name and is never resolved.
	clusterSANDNS = "notary-cluster"

	pkiDirName   = "pki"
	caCertFile   = "cluster.crt"
	caKeyFile    = "cluster.key"
	nodeCertFile = "node.crt"
	nodeKeyFile  = "node.key"

	caValidity   = 10 * 365 * 24 * time.Hour
	nodeValidity = 5 * 365 * 24 * time.Hour

	serialNumberBits = 128
)

// PKI is a node's cluster-internal identity: its own key pair, and the cluster
// CA pool it verifies its peers against.
type PKI struct {
	Certificate tls.Certificate
	Pool        *x509.CertPool
}

// PKIDir returns the directory holding the cluster-internal PKI for a node
// whose state lives in stateDir.
func PKIDir(stateDir string) string {
	return filepath.Join(stateDir, pkiDirName)
}

// EnsurePKI loads the node's cluster-internal PKI from stateDir, generating a
// new cluster CA and node certificate if none exists yet. Generating is what
// happens on bootstrap; every subsequent start loads what is already there.
//
// address is the address this node advertises to its peers; it is recorded on
// the node certificate so peers can tie a presented certificate to a member.
func EnsurePKI(stateDir string, address string) (*PKI, error) {
	dir := PKIDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create cluster PKI directory: %w", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	switch {
	case err == nil:
		return loadPKI(dir, caCertPEM)
	case errors.Is(err, os.ErrNotExist):
		return bootstrapPKI(dir, address)
	default:
		return nil, fmt.Errorf("failed to read cluster CA certificate: %w", err)
	}
}

// LoadPKI loads the cluster-internal PKI of the node whose state lives in
// stateDir, failing if there is none.
//
// Unlike EnsurePKI it never generates anything: a caller that is not starting a
// node has no business minting a fresh cluster CA, which would silently lock it
// out of the cluster it meant to talk to.
func LoadPKI(stateDir string) (*PKI, error) {
	dir := PKIDir(stateDir)
	caCertPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read cluster CA certificate: %w", err)
	}

	return loadPKI(dir, caCertPEM)
}

func loadPKI(dir string, caCertPEM []byte) (*PKI, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("cluster CA certificate is not valid PEM")
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster node key pair: %w", err)
	}

	return &PKI{Certificate: cert, Pool: pool}, nil
}

// bootstrapPKI generates a self-signed cluster CA and the first node
// certificate signed by it. The CA private key stays on this node; Phase 2's
// join flow uses it to sign the certificate signing requests of joining nodes.
func bootstrapPKI(dir string, address string) (*PKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster CA key: %w", err)
	}

	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Notary Cluster CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster CA certificate: %w", err)
	}

	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster node key: %w", err)
	}

	nodeDER, err := signNodeCertificate(caCert, caKey, &nodeKey.PublicKey, address)
	if err != nil {
		return nil, err
	}

	caCertPEM := encodeCertificate(caDER)
	caKeyPEM, err := encodePrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	nodeCertPEM := encodeCertificate(nodeDER)
	nodeKeyPEM, err := encodePrivateKey(nodeKey)
	if err != nil {
		return nil, err
	}

	files := []struct {
		name    string
		content []byte
		perm    os.FileMode
	}{
		{caKeyFile, caKeyPEM, 0o600},
		{caCertFile, caCertPEM, 0o644},
		{nodeKeyFile, nodeKeyPEM, 0o600},
		{nodeCertFile, nodeCertPEM, 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.content, f.perm); err != nil {
			return nil, fmt.Errorf("failed to write cluster PKI file %s: %w", f.name, err)
		}
	}

	return loadPKI(dir, caCertPEM)
}

// signNodeCertificate issues a cluster member certificate for the node reachable
// at address. Both the client and the server side of every dqlite connection
// present this certificate, so it carries both extended key usages.
func signNodeCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, nodePub any, address string) ([]byte, error) {
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: address},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(nodeValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{clusterSANDNS},
	}

	// Record how the node is reached, so a peer can tie the certificate it is
	// presented to the member address it dialed. clusterSANDNS must stay first.
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else if host != "" {
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, nodePub, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster node certificate: %w", err)
	}

	return der, nil
}

func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialNumberBits)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serial, nil
}

func encodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
