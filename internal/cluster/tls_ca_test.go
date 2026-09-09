package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerSANMissingRejectedOnListenAndDial(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	goodCert, goodKey := mustLeaf(t, caPEM, caKey, []string{DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	badCert, badKey := mustLeaf(t, caPEM, caKey, []string{"other.example"}, []net.IP{net.ParseIP("127.0.0.1")})

	good := CAPeer{CA: caPEM, Cert: goodCert, Key: goodKey, PeerSAN: DefaultPeerSAN}
	listen, dial, err := good.tlsConfigs()
	if err != nil {
		t.Fatal(err)
	}

	badClient := testDialTLS(t, caPEM, badCert, badKey, DefaultPeerSAN)
	if err := tlsHandshake(t, listen, badClient); err == nil {
		t.Fatal("listen must reject a peer leaf that is missing peer_san")
	}

	badListen := testListenTLS(t, caPEM, badCert, badKey, DefaultPeerSAN)
	if err := tlsHandshake(t, badListen, dial); err == nil {
		t.Fatal("dial must reject a peer leaf that is missing peer_san")
	}
}

func TestDialFailsWhenHostSANDoesNotMatchRaftAddress(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	// Group SAN present; no IP SAN for 127.0.0.1 so ServerName from the dial address fails.
	serverCert, serverKey := mustLeaf(t, caPEM, caKey, []string{DefaultPeerSAN}, nil)
	clientCert, clientKey := mustLeaf(t, caPEM, caKey, []string{DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})

	server := testListenTLS(t, caPEM, serverCert, serverKey, DefaultPeerSAN)
	client := testDialTLS(t, caPEM, clientCert, clientKey, DefaultPeerSAN)
	if err := tlsHandshake(t, server, client); err == nil {
		t.Fatal("dial must fail when the peer host SAN does not match the raft address")
	}
}

func TestPeerSANVerifiedOnSessionResume(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	serverCert, serverKey := mustLeaf(t, caPEM, caKey, []string{DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey := mustLeaf(t, caPEM, caKey, []string{DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})

	var serverChecks atomic.Int32
	listen := testListenTLS(t, caPEM, serverCert, serverKey, DefaultPeerSAN)
	inner := listen.VerifyConnection
	listen.VerifyConnection = func(cs tls.ConnectionState) error {
		serverChecks.Add(1)
		return inner(cs)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	serverErr := make(chan error, 2)
	go func() {
		for range 2 {
			conn, err := ln.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			tc := conn.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				_ = conn.Close()
				serverErr <- err
				return
			}
			_, _ = tc.Write([]byte{1})
			_ = conn.Close()
			serverErr <- nil
		}
	}()

	client := testDialTLS(t, caPEM, clientCert, clientKey, DefaultPeerSAN)
	client.ServerName = "127.0.0.1"
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	first, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := first.Read(buf); err != nil {
		t.Fatal(err)
	}
	if first.ConnectionState().DidResume {
		t.Fatal("first handshake must not resume")
	}
	_ = first.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	second, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("resumed handshake: %v", err)
	}
	if _, err := second.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !second.ConnectionState().DidResume {
		t.Fatal("second handshake must resume the TLS session")
	}
	_ = second.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if serverChecks.Load() < 2 {
		t.Fatalf("VerifyConnection ran %d times, want at least 2 (including resume)", serverChecks.Load())
	}
}

func TestCAPeerValidateRequiresPeerSANOnOwnLeaf(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	cert, key := mustLeaf(t, caPEM, caKey, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	err := CAPeer{CA: caPEM, Cert: cert, Key: key, PeerSAN: DefaultPeerSAN}.validate()
	if err == nil || !strings.Contains(err.Error(), "missing required SAN") {
		t.Fatalf("got %v", err)
	}
}

func tlsHandshake(t *testing.T, server, client *tls.Config) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close() //nolint:errcheck
		serverErr <- conn.(*tls.Conn).Handshake()
	}()

	dialCfg := client.Clone()
	if dialCfg.ServerName == "" {
		dialCfg.ServerName = "127.0.0.1"
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), dialCfg)
	if err != nil {
		<-serverErr
		return err
	}
	_ = conn.Close()
	return <-serverErr
}

func testListenTLS(t *testing.T, caPEM, certPEM, keyPEM []byte, peerSAN string) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM")
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        pool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: peerSANVerify(peerSAN),
	}
}

func testDialTLS(t *testing.T, caPEM, certPEM, keyPEM []byte, peerSAN string) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM")
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		VerifyConnection: peerSANVerify(peerSAN),
	}
}

func mustTestCA(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "notary-cluster-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func mustLeaf(t *testing.T, caPEM []byte, caKey *rsa.PrivateKey, dns []string, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "notary-unit"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
