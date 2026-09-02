package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/canonical/go-dqlite/v3/app"
)

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

func withClusterTLS(certPEM, keyPEM []byte) (app.Option, error) {
	listen, dial, err := clusterTLSConfigs(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return app.WithTLS(listen, dial), nil
}
