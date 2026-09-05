package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
)

const (
	clusterCertFile = "cluster.crt"
	clusterKeyFile  = "cluster.key"
)

// CertFingerprintPEM is the LXD-style SHA-256 fingerprint of a certificate PEM.
func CertFingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("cluster TLS certificate is not valid PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("cluster TLS certificate: %w", err)
	}
	sum := sha256.Sum256(parsed.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// PersistClusterTLS writes the shared cluster cert and key into dir.
func PersistClusterTLS(dir string, certPEM, keyPEM []byte) error {
	if dir == "" || len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, clusterCertFile), certPEM, 0o600); err != nil {
		return fmt.Errorf("write cluster certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, clusterKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write cluster key: %w", err)
	}
	return nil
}

// LoadClusterTLS reads cluster.crt and cluster.key from dir.
func LoadClusterTLS(dir string) (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(filepath.Join(dir, clusterCertFile)) // #nosec G304 -- dir is db_path from config
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = os.ReadFile(filepath.Join(dir, clusterKeyFile)) // #nosec G304 -- dir is db_path from config
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func clusterTLSConfigs(certPEM, keyPEM []byte) (*tls.Config, *tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster TLS certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("cluster TLS certificate is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("cluster TLS certificate: %w", err)
	}
	if len(parsed.DNSNames) == 0 {
		return nil, nil, fmt.Errorf("cluster TLS certificate must include a DNS SAN")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, nil, fmt.Errorf("cluster TLS certificate is not valid PEM")
	}
	listen, dial := app.SimpleTLSConfig(cert, pool)
	return listen, dial, nil
}

func generateClusterTLS() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate cluster key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("generate cluster certificate: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "notary-cluster"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", "notary-cluster"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("generate cluster certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func withClusterTLS(certPEM, keyPEM []byte) (app.Option, error) {
	listen, dial, err := clusterTLSConfigs(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return app.WithTLS(listen, dial), nil
}
