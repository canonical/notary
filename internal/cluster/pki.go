package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	nodeCertFile = "node.crt"
	nodeKeyFile  = "node.key"
)

// PKI is a node's cluster-internal identity: its own key pair, and the cluster
// CA pool it verifies its peers against.
type PKI struct {
	Certificate tls.Certificate
	Pool        *x509.CertPool
	caCert      *x509.Certificate
	nodeCert    *x509.Certificate
}

// PKIDir returns the directory holding the cluster-internal PKI for a node
// whose state lives in stateDir.
func PKIDir(stateDir string) string {
	return filepath.Join(stateDir, pkiDirName)
}

// LoadPKI loads the operator-provisioned cluster-internal PKI of the node whose
// state lives in stateDir. Notary never generates these files.
func LoadPKI(stateDir string) (*PKI, error) {
	dir := PKIDir(stateDir)
	caCertPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read cluster CA certificate: %w", err)
	}

	return loadPKI(dir, caCertPEM)
}

func loadPKI(dir string, caCertPEM []byte) (*PKI, error) {
	if err := rejectWorldReadable(filepath.Join(dir, nodeKeyFile)); err != nil {
		return nil, err
	}

	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("cluster CA certificate is unusable: %w", err)
	}
	if !caCert.IsCA {
		return nil, errors.New("cluster CA certificate is not a CA")
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster node key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("cluster node certificate is empty")
	}
	nodeCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster node certificate: %w", err)
	}

	if _, err := nodeCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("the node certificate does not chain to the cluster CA: %w", err)
	}
	if err := requireClientAndServerAuth(nodeCert); err != nil {
		return nil, err
	}
	if len(nodeCert.DNSNames) == 0 || nodeCert.DNSNames[0] != clusterSANDNS {
		return nil, fmt.Errorf("cluster node certificate must list %q as its first DNS SAN", clusterSANDNS)
	}

	return &PKI{Certificate: cert, Pool: pool, caCert: caCert, nodeCert: nodeCert}, nil
}

// MatchesIdentity reports whether this node's certificate is bound to identity,
// which is the advertise address a join token is issued for.
func (p *PKI) MatchesIdentity(identity string) error {
	if p == nil || p.nodeCert == nil {
		return errors.New("cluster node certificate is missing")
	}
	if err := ParseAdvertiseAddress(identity); err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(identity)
	if err != nil {
		host = identity
	}

	if p.nodeCert.Subject.CommonName == identity || p.nodeCert.Subject.CommonName == host {
		return nil
	}
	for _, name := range p.nodeCert.DNSNames {
		if name == host || name == identity {
			return nil
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range p.nodeCert.IPAddresses {
			if certIP.Equal(ip) {
				return nil
			}
		}
	}

	return fmt.Errorf("cluster node certificate is not bound to %q", identity)
}

func requireClientAndServerAuth(cert *x509.Certificate) error {
	var client, server bool
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			client = true
		}
		if usage == x509.ExtKeyUsageServerAuth {
			server = true
		}
	}
	if !client || !server {
		return errors.New("cluster node certificate must allow both client and server authentication")
	}
	return nil
}

func rejectWorldReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat cluster node key: %w", err)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("cluster node key %s must not be world-accessible", path)
	}
	return nil
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
