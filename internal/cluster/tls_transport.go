package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/canonical/go-dqlite/v3/app"
	"github.com/canonical/go-dqlite/v3/client"
)

// TransportTLS is dqlite mTLS. Use SharedPair (default, one identity) or
// CAPeer (per-unit leaf + group SAN). Never both; nil is plaintext or
// "load/generate shared" in Start.
type TransportTLS interface {
	tlsConfigs() (listen, dial *tls.Config, err error)
	persist(dir string) error
	// redeemPair is the shared cluster cert/key handed out at join redeem.
	// ok is false in CA mode: redeem must not return a private key.
	redeemPair() (cert, key []byte, ok bool)
}

// SharedPair is the zero-config cluster certificate: the same PEM on every
// member, also the trust store. Anyone holding the key can speak dqlite.
type SharedPair struct {
	Cert []byte
	Key  []byte
}

func (s SharedPair) tlsConfigs() (listen, dial *tls.Config, err error) {
	return clusterTLSConfigs(s.Cert, s.Key)
}

func (s SharedPair) persist(dir string) error {
	return PersistClusterTLS(dir, s.Cert, s.Key)
}

func (s SharedPair) redeemPair() ([]byte, []byte, bool) {
	if len(s.Cert) == 0 || len(s.Key) == 0 {
		return nil, nil, false
	}
	return s.Cert, s.Key, true
}

// CAPeer is per-unit cluster TLS: a dedicated CA, this unit's leaf, and a
// group SAN that every peer leaf must carry. Trust is the CA plus peer_san;
// there is no second authz layer on the dqlite port.
type CAPeer struct {
	CA      []byte
	Cert    []byte
	Key     []byte
	PeerSAN string
}

func (c CAPeer) tlsConfigs() (listen, dial *tls.Config, err error) {
	if err := c.validate(); err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster TLS certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CA) {
		return nil, nil, fmt.Errorf("cluster TLS CA is not valid PEM")
	}
	verify := peerSANVerify(c.PeerSAN)
	listen = &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        pool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: verify,
	}
	// ServerName left empty: DialFuncWithTLS sets it from the dial address.
	dial = &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		VerifyConnection: verify,
	}
	return listen, dial, nil
}

func (c CAPeer) persist(string) error { return nil }

func (c CAPeer) redeemPair() ([]byte, []byte, bool) { return nil, nil, false }

func (c CAPeer) validate() error {
	if len(c.CA) == 0 || len(c.Cert) == 0 || len(c.Key) == 0 || c.PeerSAN == "" {
		return errors.New("CA mode requires cluster.tls.ca_path, cert_path, key_path, and peer_san")
	}
	cert, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return fmt.Errorf("cluster TLS certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("cluster TLS certificate is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("cluster TLS certificate: %w", err)
	}
	if !certHasPeerSAN(parsed, c.PeerSAN) {
		return fmt.Errorf("cluster TLS certificate is missing required SAN %q", c.PeerSAN)
	}
	return nil
}

// peerSANVerify runs on full and resumed handshakes. VerifyPeerCertificate is
// skipped when a session is resumed; VerifyConnection is not.
func peerSANVerify(peerSAN string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
			return fmt.Errorf("peer certificate was not verified")
		}
		if !certHasPeerSAN(cs.VerifiedChains[0][0], peerSAN) {
			return fmt.Errorf("peer certificate is missing required SAN %q", peerSAN)
		}
		return nil
	}
}

func certHasPeerSAN(cert *x509.Certificate, peerSAN string) bool {
	if cert == nil || peerSAN == "" {
		return false
	}
	for _, d := range cert.DNSNames {
		if d == peerSAN {
			return true
		}
	}
	for _, u := range cert.URIs {
		if u != nil && u.String() == peerSAN {
			return true
		}
	}
	return false
}

func tlsFromCertKey(certPEM, keyPEM []byte) TransportTLS {
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil
	}
	return SharedPair{Cert: certPEM, Key: keyPEM}
}

func withTransportTLS(t TransportTLS) (app.Option, error) {
	listen, dial, err := t.tlsConfigs()
	if err != nil {
		return nil, err
	}
	return app.WithTLS(listen, dial), nil
}

func dialFunc(t TransportTLS) (client.DialFunc, error) {
	if t == nil {
		return client.DefaultDialFunc, nil
	}
	_, dialTLS, err := t.tlsConfigs()
	if err != nil {
		return nil, err
	}
	return client.DialFuncWithTLS(client.DefaultDialFunc, dialTLS), nil
}

func presentCertKey(t TransportTLS) (cert, key []byte) {
	switch v := t.(type) {
	case SharedPair:
		return v.Cert, v.Key
	case CAPeer:
		return v.Cert, v.Key
	default:
		return nil, nil
	}
}

// PresentCertKey returns the leaf this node presents for dqlite mTLS.
func PresentCertKey(t TransportTLS) (cert, key []byte) {
	return presentCertKey(t)
}

// RedeemPair is the shared cluster cert/key to return at join redeem.
// ok is false in CA mode.
func RedeemPair(t TransportTLS) (cert, key []byte, ok bool) {
	if t == nil {
		return nil, nil, false
	}
	return t.redeemPair()
}
