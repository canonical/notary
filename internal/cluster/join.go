package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const joinRedeemPath = "/api/v1/cluster/join"

// JoinMaterial is cluster TLS and dqlite addresses returned after a token is redeemed.
type JoinMaterial struct {
	TLSCert    []byte
	TLSKey     []byte
	Join       []string
	ServerName string
}

type joinRedeemRequest struct {
	JoinToken string `json:"join_token"`
}

type joinRedeemData struct {
	ClusterCertificate string   `json:"cluster_certificate"`
	ClusterPrivateKey  string   `json:"cluster_private_key"`
	Addresses          []string `json:"addresses"`
	ServerName         string   `json:"server_name"`
}

type joinRedeemResponse struct {
	Message string         `json:"message"`
	Data    joinRedeemData `json:"data"`
}

// ExchangeJoinToken redeems a join ticket over HTTPS, pinning the server with
// the token fingerprint. Tests may replace this.
var ExchangeJoinToken = ExchangeJoinTokenHTTPS

// JoinAPIAddress is the HTTPS host:port joiners use to redeem a token.
// The config default external_hostname is localhost (CRL/OIDC). That is not a
// join URL when this node binds a wildcard or a routable cluster address.
func JoinAPIAddress(clusterAddress string, port int, externalHostname string) (string, error) {
	if port <= 0 {
		port = 8000
	}
	clusterHost := "127.0.0.1"
	if clusterAddress != "" {
		if h, _, err := net.SplitHostPort(clusterAddress); err == nil && h != "" {
			clusterHost = h
		}
	}
	if h := strings.TrimSpace(externalHostname); h != "" {
		addr := joinAddressWithPort(h, port)
		if err := joinAddressReachable(addr, clusterHost); err == nil {
			return addr, nil
		}
	}
	return requireReachableJoinAddress(net.JoinHostPort(clusterHost, strconv.Itoa(port)), clusterHost)
}

func joinAddressWithPort(host string, port int) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func requireReachableJoinAddress(addr, clusterHost string) (string, error) {
	if err := joinAddressReachable(addr, clusterHost); err != nil {
		return "", err
	}
	return addr, nil
}

func joinAddressReachable(addr, clusterHost string) error {
	if joinHostUnspecified(addr) {
		return fmt.Errorf("%w (got %q)", ErrUnreachableJoinAddress, addr)
	}
	// Loopback is only reachable for joiners on this machine. Allow it when
	// dqlite also binds loopback; reject it for wildcard or routable binds.
	if joinHostLoopback(addr) && !joinHostLoopback(clusterHost) {
		return fmt.Errorf("%w (got %q)", ErrUnreachableJoinAddress, addr)
	}
	return nil
}

func joinHostPart(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]")
	}
	return host
}

func joinHostUnspecified(addr string) bool {
	ip := net.ParseIP(joinHostPart(addr))
	return ip != nil && ip.IsUnspecified()
}

func joinHostLoopback(addr string) bool {
	host := joinHostPart(addr)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requireReachableJoinAddresses(addresses []string) error {
	for _, a := range addresses {
		if joinHostUnspecified(a) {
			return fmt.Errorf("%w (got %q)", ErrUnreachableJoinAddress, a)
		}
	}
	return nil
}

// RedeemJoinToken consumes a one-time ticket and returns cluster TLS.
func RedeemJoinToken(ctx context.Context, sqldb *sql.DB, token JoinToken, clusterCert, clusterKey []byte) (JoinMaterial, error) {
	if len(clusterCert) == 0 || len(clusterKey) == 0 {
		return JoinMaterial{}, fmt.Errorf("cluster TLS is required to join")
	}
	if err := consumeJoinToken(ctx, sqldb, token.ServerName, token.Secret); err != nil {
		return JoinMaterial{}, err
	}
	return JoinMaterial{
		TLSCert:    clusterCert,
		TLSKey:     clusterKey,
		ServerName: token.ServerName,
	}, nil
}

// ExchangeJoinTokenHTTPS redeems the token at the issuing member's HTTPS address.
func ExchangeJoinTokenHTTPS(ctx context.Context, rawToken string) (JoinMaterial, error) {
	token, err := DecodeJoinToken(rawToken)
	if err != nil {
		return JoinMaterial{}, err
	}
	if len(token.Addresses) == 0 {
		return JoinMaterial{}, fmt.Errorf("join token has no addresses")
	}
	return redeemAt(ctx, rawToken, token.Fingerprint, token.Addresses[0])
}

func redeemAt(ctx context.Context, rawToken, fingerprint, addr string) (JoinMaterial, error) {
	body, err := json.Marshal(joinRedeemRequest{JoinToken: rawToken})
	if err != nil {
		return JoinMaterial{}, err
	}
	url := "https://" + addr + joinRedeemPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return JoinMaterial{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := pinnedHTTPClient(fingerprint).Do(req)
	if err != nil {
		return JoinMaterial{}, fmt.Errorf("redeem join token at %s: %w", addr, err)
	}
	defer res.Body.Close() //nolint:errcheck
	payload, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return JoinMaterial{}, err
	}
	if res.StatusCode != http.StatusOK {
		var parsed joinRedeemResponse
		_ = json.Unmarshal(payload, &parsed)
		if parsed.Message != "" {
			return JoinMaterial{}, fmt.Errorf("redeem join token: %s", parsed.Message)
		}
		return JoinMaterial{}, fmt.Errorf("redeem join token at %s: HTTP %d", addr, res.StatusCode)
	}
	var parsed joinRedeemResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return JoinMaterial{}, fmt.Errorf("parse join credentials: %w", err)
	}
	if parsed.Data.ClusterCertificate == "" || parsed.Data.ClusterPrivateKey == "" || len(parsed.Data.Addresses) == 0 {
		return JoinMaterial{}, fmt.Errorf("join credentials are incomplete")
	}
	return JoinMaterial{
		TLSCert:    []byte(parsed.Data.ClusterCertificate),
		TLSKey:     []byte(parsed.Data.ClusterPrivateKey),
		Join:       parsed.Data.Addresses,
		ServerName: parsed.Data.ServerName,
	}, nil
}

func pinnedHTTPClient(fingerprint string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// The joiner has no CA for this cluster yet, so the peer is pinned by
				// fingerprint instead. VerifyConnection rather than VerifyPeerCertificate
				// because the latter is skipped on a resumed session.
				InsecureSkipVerify:     true, // #nosec G402 -- peer is pinned in VerifyConnection
				SessionTicketsDisabled: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("server presented no certificate")
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
					if !strings.EqualFold(hex.EncodeToString(sum[:]), fingerprint) {
						return fmt.Errorf("server certificate does not match join token fingerprint")
					}
					return nil
				},
			},
		},
	}
}
