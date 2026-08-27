package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/server"
)

// clusterAPITimeout bounds a single admin API call made by the cluster CLI.
const clusterAPITimeout = 30 * time.Second

// apiTokenEnvVar is where the CLI looks for the admin token when --token is not
// given, so the token does not have to appear in shell history or process args.
const apiTokenEnvVar = "NOTARY_TOKEN" //nolint:gosec // name of an env var, not a credential

// apiResponse mirrors the envelope every Notary API handler writes.
type apiResponse struct {
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// apiClient talks to a running Notary node's admin API. The cluster CLI cannot
// touch dqlite directly: the running node holds its data directory open.
type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
	// advertised is the host:port a *different* machine would use to reach this
	// node, empty when the configuration does not say. It is only for display.
	advertised string
}

// newLocalAPIClient builds a client for the node described by a config file. The
// node's own TLS certificate is used as the trust anchor, so a self-signed
// deployment needs no extra flags and no verification is skipped.
func newLocalAPIClient(appConfig *config.AppConfig, token string) (*apiClient, error) {
	if token == "" {
		return nil, fmt.Errorf("an admin token is required: pass --token or set %s", apiTokenEnvVar)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(appConfig.TLSCertificate) {
		return nil, errors.New("couldn't parse the TLS certificate from the configuration file")
	}

	host := apiHostPort(appConfig)

	return &apiClient{
		baseURL:    fmt.Sprintf("https://%s/api/v1", host),
		token:      token,
		advertised: advertisedAddress(host),
		http: &http.Client{
			Timeout:   clusterAPITimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// apiHostPort resolves the host:port of the node's own API.
//
// external_hostname may already carry a port, in which case appending the
// configured one would build an unusable address.
func apiHostPort(appConfig *config.AppConfig) string {
	host := appConfig.ExternalHostname
	if host == "" {
		host = "localhost"
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	return net.JoinHostPort(host, strconv.Itoa(appConfig.Port))
}

// advertisedAddress returns the address another machine would dial to reach this
// node, or empty when the configuration only describes a loopback address.
//
// A joining node is on a different host, so telling it to contact localhost
// would send it to itself.
func advertisedAddress(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return ""
	}

	if strings.EqualFold(host, "localhost") {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return ""
	}

	return hostPort
}

// newJoinAPIClient builds a client for an existing member's admin API, used by a
// node that has not joined yet. It carries no admin token: the join token in the
// request body is the credential (spec §1.2).
//
// caCertPath is required so the join cannot be intercepted by a host presenting
// any certificate the system trust store would accept.
func newJoinAPIClient(address string, caCertPath string) (*apiClient, error) {
	if caCertPath == "" {
		return nil, errors.New("--ca-cert is required: pin the existing member's API certificate")
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't read %s: %w", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("%s does not contain a PEM certificate", caCertPath)
	}

	return &apiClient{
		baseURL: fmt.Sprintf("https://%s/api/v1", address),
		http: &http.Client{
			Timeout:   clusterAPITimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// do performs one API call and unmarshals the response envelope's data field
// into out, which may be nil when the caller only cares whether it succeeded.
func (c *apiClient) do(method, path string, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("couldn't encode request: %w", err)
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("couldn't build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.AddCookie(&http.Cookie{
			Name:     server.CookieSessionTokenKey,
			Value:    c.token,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't reach the Notary API at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var envelope apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("couldn't decode the API response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Message == "" {
			return fmt.Errorf("the API returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("the API returned status %d: %s", resp.StatusCode, envelope.Message)
	}
	if out == nil || len(envelope.Data) == 0 {
		return nil
	}

	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("couldn't decode the API response: %w", err)
	}

	return nil
}
