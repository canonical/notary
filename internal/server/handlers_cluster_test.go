package server_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
)

// mustSchemaVersion is the migration version a joining node has to declare to be
// admitted into a cluster running this binary.
func mustSchemaVersion(t *testing.T) int64 {
	t.Helper()

	version, err := db.EmbeddedSchemaVersion()
	if err != nil {
		t.Fatalf("couldn't read the embedded schema version: %s", err)
	}
	return version
}

func decodeClusterResponse[T any](t *testing.T, body []byte) tu.APIResponse[T] {
	t.Helper()

	var response tu.APIResponse[T]
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("couldn't decode response %q: %s", string(body), err)
	}
	return response
}

func fakeThreeNodeCluster() *tu.FakeClusterNode {
	return &tu.FakeClusterNode{
		NodeID:      1,
		NodeAddress: "10.0.0.1:9000",
		LeaderID:    1,
		MemberList: []cluster.MemberInfo{
			{ID: 1, Address: "10.0.0.1:9000", Role: cluster.RoleVoter},
			{ID: 2, Address: "10.0.0.2:9000", Role: cluster.RoleVoter},
			{ID: 3, Address: "10.0.0.3:9000", Role: cluster.RoleStandBy},
		},
	}
}

// With clustering off the cluster API must not exist at all, rather than report
// an empty cluster.
func TestClusterAPIIsAbsentWhenClusteringIsDisabled(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/cluster/members"},
		{"GET", "/api/v1/cluster/status"},
		{"POST", "/api/v1/cluster/members/tokens"},
		{"POST", "/api/v1/cluster/members/join"},
		{"POST", "/api/v1/cluster/members/2/promote"},
		{"DELETE", "/api/v1/cluster/members/2"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			statusCode, _ := tu.DoClusterAPIRequest(t, ts, tt.method, tt.path, adminToken, nil)
			if statusCode != http.StatusNotFound {
				t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
			}
		})
	}
}

func TestClusterAPIRequiresAdmin(t *testing.T) {
	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/cluster/members"},
		{"GET", "/api/v1/cluster/status"},
		{"POST", "/api/v1/cluster/members/tokens"},
		{"POST", "/api/v1/cluster/members/2/promote"},
		{"DELETE", "/api/v1/cluster/members/2"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Run("no token", func(t *testing.T) {
				statusCode, _ := tu.DoClusterAPIRequest(t, ts, tt.method, tt.path, "", nil)
				if statusCode != http.StatusUnauthorized {
					t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
				}
			})
			t.Run("non-admin token", func(t *testing.T) {
				statusCode, _ := tu.DoClusterAPIRequest(t, ts, tt.method, tt.path, nonAdminToken, nil)
				if statusCode != http.StatusForbidden {
					t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
				}
			})
		})
	}
}

func TestClusterStatusReportsMembership(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "GET", "/api/v1/cluster/status", adminToken, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
	}

	status := decodeClusterResponse[server.ClusterStatusResponse](t, body).Data
	if !status.Enabled {
		t.Error("expected clustering to be reported as enabled")
	}
	if status.NodeID != "1" || status.Address != "10.0.0.1:9000" {
		t.Errorf("got node %q at %q, want 1 at 10.0.0.1:9000", status.NodeID, status.Address)
	}
	if status.LeaderID != "1" {
		t.Errorf("got leader %q, want 1", status.LeaderID)
	}
	if status.Voters != 2 {
		t.Errorf("got %d voters, want 2", status.Voters)
	}
	if len(status.Members) != 3 {
		t.Fatalf("got %d members, want 3", len(status.Members))
	}
	if !status.Members[0].Leader || status.Members[1].Leader {
		t.Error("the leader flag is not set on exactly the leading member")
	}
}

// dqlite knows node IDs and addresses; the operator-assigned names live in
// Notary's own table, and the two have to be reported together.
func TestListClusterMembersJoinsRecordedNames(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "GET", "/api/v1/cluster/members", adminToken, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
	}

	members := decodeClusterResponse[[]server.ClusterMemberResponse](t, body).Data
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
	// No names have been recorded yet, so members must still be listed.
	for _, member := range members {
		if member.Name != "" {
			t.Errorf("got name %q for member %q, want none", member.Name, member.ID)
		}
		if member.Address == "" {
			t.Errorf("member %q has no address", member.ID)
		}
	}
	if members[2].Role != string(cluster.RoleStandBy) {
		t.Errorf("got role %q, want %q", members[2].Role, cluster.RoleStandBy)
	}
}

// A member is ONLINE only while its own heartbeat is recent; nobody polls it,
// so a node that stops writing simply ages out (spec §6.2).
func TestListClusterMembersReportsLivenessAndSealState(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, database := tu.MustPrepareClusterServerWithDatabase(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	now := time.Now().UTC()
	if _, err := database.CreateClusterMember("1", "node-1", "10.0.0.1:9000", now); err != nil {
		t.Fatalf("Couldn't record member 1: %s", err)
	}
	if _, err := database.CreateClusterMember("2", "node-2", "10.0.0.2:9000", now); err != nil {
		t.Fatalf("Couldn't record member 2: %s", err)
	}
	// 1 beat just now and is sealed, 2 beat long ago, 3 has never beaten.
	if err := database.RecordClusterMemberHeartbeat("1", "10.0.0.1:9000", true, now); err != nil {
		t.Fatalf("Couldn't record a heartbeat: %s", err)
	}
	if err := database.RecordClusterMemberHeartbeat("2", "10.0.0.2:9000", false, now.Add(-2*db.OfflineThreshold)); err != nil {
		t.Fatalf("Couldn't record a stale heartbeat: %s", err)
	}

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "GET", "/api/v1/cluster/members", adminToken, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
	}
	members := decodeClusterResponse[[]server.ClusterMemberResponse](t, body).Data
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}

	byID := map[string]server.ClusterMemberResponse{}
	for _, member := range members {
		byID[member.ID] = member
	}

	if got := byID["1"]; got.Status != server.MemberStatusOnline || !got.Sealed || got.LastSeen != now.Unix() {
		t.Errorf("member 1: got status %q sealed %t last_seen %d, want ONLINE sealed at %d",
			got.Status, got.Sealed, got.LastSeen, now.Unix())
	}
	if got := byID["2"]; got.Status != server.MemberStatusOffline {
		t.Errorf("member 2: got status %q, want %q", got.Status, server.MemberStatusOffline)
	}
	if got := byID["3"]; got.Status != server.MemberStatusOffline || got.LastSeen != 0 {
		t.Errorf("member 3 never beat: got status %q last_seen %d, want OFFLINE at 0", got.Status, got.LastSeen)
	}
	for id, member := range byID {
		if member.Message == "" {
			t.Errorf("member %s has no message", id)
		}
	}
}

func TestClusterAPIReportsUnreachableCluster(t *testing.T) {
	node := fakeThreeNodeCluster()
	node.Err = errors.New("no leader available")
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, _ := tu.DoClusterAPIRequest(t, ts, "GET", "/api/v1/cluster/status", adminToken, nil)
	if statusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, statusCode)
	}
}

func TestCreateClusterJoinTokenValidatesInput(t *testing.T) {
	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"empty body uses the default ttl", "", http.StatusCreated},
		{"empty object uses the default ttl", `{}`, http.StatusCreated},
		{"negative ttl", `{"ttl_seconds":-1}`, http.StatusBadRequest},
		{"ttl beyond the maximum", `{"ttl_seconds":90000}`, http.StatusBadRequest},
		{"ttl within the maximum", `{"ttl_seconds":600}`, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != "" {
				body = []byte(tt.body)
			}
			statusCode, responseBody := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/tokens", adminToken, body)
			if statusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, statusCode, string(responseBody))
			}
			if tt.wantStatus != http.StatusCreated {
				return
			}
			response := decodeClusterResponse[server.CreateJoinTokenResponse](t, responseBody).Data
			if response.Token == "" {
				t.Error("no token was returned")
			}
			if response.ExpiresAt == 0 {
				t.Error("no expiry was returned")
			}
		})
	}
}

// A join token is single use, so a request the member was never going to be
// able to serve must leave it usable rather than silently spending it.
func TestRejectedJoinRequestsDoNotSpendTheToken(t *testing.T) {
	const joinerAddress = "10.0.0.4:9000"

	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/tokens", adminToken, nil)
	if statusCode != http.StatusCreated {
		t.Fatalf("couldn't create a join token: %d %s", statusCode, string(body))
	}
	token := decodeClusterResponse[server.CreateJoinTokenResponse](t, body).Data.Token

	schemaVersion := mustSchemaVersion(t)
	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}

	rejected := []struct {
		name       string
		params     server.JoinClusterParams
		wantStatus int
	}{
		{
			"malformed csr",
			server.JoinClusterParams{Token: token, Address: joinerAddress, CSR: "not a csr", SchemaVersion: schemaVersion},
			http.StatusBadRequest,
		},
		{
			"mismatched schema version",
			server.JoinClusterParams{Token: token, Address: joinerAddress, CSR: string(csrPEM), SchemaVersion: schemaVersion + 1},
			http.StatusConflict,
		},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tt.params)
			if err != nil {
				t.Fatalf("couldn't build the join request: %s", err)
			}
			statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", requestBody)
			if statusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, statusCode, string(body))
			}
		})
	}

	// The token survived every rejection and still admits a valid request.
	requestBody, err := json.Marshal(server.JoinClusterParams{
		Token:         token,
		Address:       joinerAddress,
		CSR:           string(csrPEM),
		SchemaVersion: schemaVersion,
	})
	if err != nil {
		t.Fatalf("couldn't build the join request: %s", err)
	}
	statusCode, body = tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", requestBody)
	if statusCode != http.StatusOK {
		t.Fatalf("the token was spent by a rejected request: %d %s", statusCode, string(body))
	}
}

func TestJoinClusterEndToEnd(t *testing.T) {
	const joinerAddress = "10.0.0.4:9000"

	node := fakeThreeNodeCluster()
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/tokens", adminToken, nil)
	if statusCode != http.StatusCreated {
		t.Fatalf("couldn't create a join token: %d %s", statusCode, string(body))
	}
	token := decodeClusterResponse[server.CreateJoinTokenResponse](t, body).Data.Token

	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	joinBody, err := json.Marshal(server.JoinClusterParams{
		Token:         token,
		Address:       joinerAddress,
		CSR:           string(csrPEM),
		SchemaVersion: mustSchemaVersion(t),
	})
	if err != nil {
		t.Fatalf("couldn't build the join request: %s", err)
	}

	// The joining node has no account and no cluster certificate yet: the join
	// token is the only credential it presents.
	statusCode, body = tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", joinBody)
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
	}
	joinResponse := decodeClusterResponse[server.JoinClusterResponse](t, body).Data

	if len(joinResponse.MemberAddress) != 3 {
		t.Errorf("got %d peer addresses, want 3", len(joinResponse.MemberAddress))
	}

	// The join endpoint is authenticated only by a single-use token, so nothing
	// it returns may be a lasting credential.
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Error("the join response carries a private key")
	}

	if err := cluster.CompleteJoin(joinerDir, []byte(joinResponse.Certificate), []byte(joinResponse.CACertificate)); err != nil {
		t.Fatalf("couldn't complete the join: %s", err)
	}
	pki, err := cluster.EnsurePKI(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't load the joined node's PKI: %s", err)
	}
	cert, err := x509.ParseCertificate(pki.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("couldn't parse the issued certificate: %s", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pki.Pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("the issued certificate does not verify against the cluster CA: %s", err)
	}

	// A join token authorizes exactly one node.
	statusCode, _ = tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", joinBody)
	if statusCode != http.StatusUnauthorized {
		t.Fatalf("expected the reused token to be rejected with %d, got %d", http.StatusUnauthorized, statusCode)
	}
}

// A node whose migrations differ from the cluster's must not be admitted: it
// would replicate a schema its binary was not built for (spec §4.1).
func TestJoinClusterRejectsAMismatchedSchemaVersion(t *testing.T) {
	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/tokens", adminToken, nil)
	if statusCode != http.StatusCreated {
		t.Fatalf("couldn't create a join token: %d %s", statusCode, string(body))
	}
	token := decodeClusterResponse[server.CreateJoinTokenResponse](t, body).Data.Token

	csrPEM, err := cluster.PrepareJoin(t.TempDir(), "10.0.0.4:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	joinBody, err := json.Marshal(server.JoinClusterParams{
		Token:         token,
		Address:       "10.0.0.4:9000",
		CSR:           string(csrPEM),
		SchemaVersion: mustSchemaVersion(t) - 1,
	})
	if err != nil {
		t.Fatalf("couldn't build the join request: %s", err)
	}

	statusCode, body = tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", joinBody)
	if statusCode != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, statusCode, string(body))
	}
	if block, _ := pem.Decode(body); block != nil {
		t.Error("a certificate was returned despite the schema version mismatch")
	}
}

func TestJoinClusterRejectsBadRequests(t *testing.T) {
	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/tokens", adminToken, nil)
	if statusCode != http.StatusCreated {
		t.Fatalf("couldn't create a join token: %d %s", statusCode, string(body))
	}
	token := decodeClusterResponse[server.CreateJoinTokenResponse](t, body).Data.Token

	csrPEM, err := cluster.PrepareJoin(t.TempDir(), "10.0.0.4:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}

	tests := []struct {
		name       string
		body       any
		wantStatus int
	}{
		{"missing fields", server.JoinClusterParams{Token: token}, http.StatusBadRequest},
		{"unknown token", server.JoinClusterParams{Token: "nope", Address: "10.0.0.4:9000", CSR: string(csrPEM)}, http.StatusUnauthorized},
		{"valid token, unusable csr", server.JoinClusterParams{Token: token, Address: "10.0.0.4:9000", CSR: "not a csr", SchemaVersion: mustSchemaVersion(t)}, http.StatusBadRequest},
	}

	t.Run("not json", func(t *testing.T) {
		statusCode, _ := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", []byte("nonsense"))
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("couldn't build the join request: %s", err)
			}
			statusCode, _ := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", requestBody)
			if statusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, statusCode)
			}
		})
	}
}

// An invalid token must not be distinguishable from an unknown one, and neither
// must reveal anything about the CSR that was sent with it.
func TestJoinClusterDoesNotSignWithoutAValidToken(t *testing.T) {
	ts, _ := tu.MustPrepareClusterServer(t, fakeThreeNodeCluster())

	csrPEM, err := cluster.PrepareJoin(t.TempDir(), "10.0.0.4:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	joinBody, err := json.Marshal(server.JoinClusterParams{
		Token:   "not-a-real-token",
		Address: "10.0.0.4:9000",
		CSR:     string(csrPEM),
	})
	if err != nil {
		t.Fatalf("couldn't build the join request: %s", err)
	}

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/join", "", joinBody)
	if statusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
	}
	if block, _ := pem.Decode(body); block != nil {
		t.Error("a certificate was returned despite the invalid token")
	}
}

// A member that is already gone cannot hand anything over, which is the case
// force exists for.
func TestRemoveClusterMemberRequiresForceWhenHandoverFails(t *testing.T) {
	node := fakeThreeNodeCluster()
	node.HandoverErr = errors.New("member is unreachable")
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	statusCode, _ := tu.DoClusterAPIRequest(t, ts, "DELETE", "/api/v1/cluster/members/3", adminToken, nil)
	if statusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, statusCode)
	}
	if removed := node.Removed(); len(removed) != 0 {
		t.Fatalf("the member was removed despite the failed handover: %v", removed)
	}

	statusCode, body := tu.DoClusterAPIRequest(t, ts, "DELETE", "/api/v1/cluster/members/3?force=true", adminToken, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
	}
	if removed := node.Removed(); len(removed) != 1 || removed[0] != 3 {
		t.Fatalf("got removals %v, want [3]", removed)
	}
}

// Removing the member serving the request would take away the node the caller
// is talking to, and with force it would do so without handing over first.
func TestAClusterMemberCannotRemoveItself(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	for _, path := range []string{
		"/api/v1/cluster/members/1",
		"/api/v1/cluster/members/1?force=true",
	} {
		t.Run(path, func(t *testing.T) {
			statusCode, body := tu.DoClusterAPIRequest(t, ts, "DELETE", path, adminToken, nil)
			if statusCode != http.StatusConflict {
				t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, statusCode, string(body))
			}
			if removed := node.Removed(); len(removed) != 0 {
				t.Fatalf("the local member was removed: %v", removed)
			}
		})
	}
}

func TestPromoteAndRemoveClusterMember(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, _ := tu.MustPrepareClusterServer(t, node)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	t.Run("promote", func(t *testing.T) {
		statusCode, body := tu.DoClusterAPIRequest(t, ts, "POST", "/api/v1/cluster/members/3/promote", adminToken, nil)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
		}
		if promoted := node.Promoted(); len(promoted) != 1 || promoted[0] != 3 {
			t.Fatalf("got promotions %v, want [3]", promoted)
		}
	})

	t.Run("remove", func(t *testing.T) {
		statusCode, body := tu.DoClusterAPIRequest(t, ts, "DELETE", "/api/v1/cluster/members/3", adminToken, nil)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d: %s", http.StatusOK, statusCode, string(body))
		}
		if removed := node.Removed(); len(removed) != 1 || removed[0] != 3 {
			t.Fatalf("got removals %v, want [3]", removed)
		}
		if handedOver := node.HandedOver(); len(handedOver) != 1 || handedOver[0] != 3 {
			t.Fatalf("got handovers %v, want [3]", handedOver)
		}
	})

	t.Run("invalid member id", func(t *testing.T) {
		for _, path := range []string{"/api/v1/cluster/members/abc/promote", "/api/v1/cluster/members/abc"} {
			method := "POST"
			if path == "/api/v1/cluster/members/abc" {
				method = "DELETE"
			}
			statusCode, _ := tu.DoClusterAPIRequest(t, ts, method, path, adminToken, nil)
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d for %s, got %d", http.StatusBadRequest, path, statusCode)
			}
		}
	})
}
