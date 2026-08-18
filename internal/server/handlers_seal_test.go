package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
)

type sealedStatusResponse struct {
	Message string                `json:"message,omitempty"`
	Data    server.StatusResponse `json:"data"`
}

// A sealed node answers /status, /metrics and the read-only cluster routes so an
// operator can see what is wrong, and refuses everything else with 503. There is
// no unseal endpoint: the node retries its encryption backend on its own.
func TestSealedNodeServesOnlyObservabilityRoutes(t *testing.T) {
	node := &tu.FakeClusterNode{
		NodeID:      1,
		NodeAddress: "10.0.0.1:9000",
		LeaderID:    1,
		MemberList: []cluster.MemberInfo{
			{ID: 1, Address: "10.0.0.1:9000", Role: cluster.RoleVoter},
		},
	}
	ts, sealState := tu.MustPrepareSealedClusterServer(t, node)

	available := []struct {
		name   string
		method string
		path   string
	}{
		{"status", http.MethodGet, "/status"},
		{"metrics", http.MethodGet, "/metrics"},
		{"cluster members", http.MethodGet, "/api/v1/cluster/members"},
		{"cluster status", http.MethodGet, "/api/v1/cluster/status"},
	}
	for _, route := range available {
		t.Run("available while sealed: "+route.name, func(t *testing.T) {
			statusCode, _ := tu.DoClusterAPIRequest(t, ts, route.method, route.path, "", nil)
			if statusCode == http.StatusServiceUnavailable {
				t.Fatalf("expected %s %s to stay available while sealed, got %d", route.method, route.path, statusCode)
			}
		})
	}

	gated := []struct {
		name   string
		method string
		path   string
	}{
		{"login", http.MethodPost, "/login"},
		{"list certificate requests", http.MethodGet, "/api/v1/certificate_requests"},
		{"list accounts", http.MethodGet, "/api/v1/accounts"},
		{"create account", http.MethodPost, "/api/v1/accounts"},
		{"create join token", http.MethodPost, "/api/v1/cluster/members/tokens"},
		{"join cluster", http.MethodPost, "/api/v1/cluster/members/join"},
		{"promote member", http.MethodPost, "/api/v1/cluster/members/1/promote"},
		{"remove member", http.MethodDelete, "/api/v1/cluster/members/1"},
	}
	for _, route := range gated {
		t.Run("gated while sealed: "+route.name, func(t *testing.T) {
			statusCode, body := tu.DoClusterAPIRequest(t, ts, route.method, route.path, "", []byte("{}"))
			if statusCode != http.StatusServiceUnavailable {
				t.Fatalf("expected %s %s to return %d while sealed, got %d: %s", route.method, route.path, http.StatusServiceUnavailable, statusCode, body)
			}
			if !strings.Contains(string(body), "encryption key") {
				t.Fatalf("expected the response to explain the node is sealed, got %s", body)
			}
		})
	}

	// The node unseals itself once its backend is reachable; nothing restarts.
	sealState.Unseal()

	t.Run("gated routes resume once unsealed", func(t *testing.T) {
		statusCode, body := tu.DoClusterAPIRequest(t, ts, http.MethodGet, "/api/v1/accounts", "", nil)
		if statusCode == http.StatusServiceUnavailable {
			t.Fatalf("expected the route to resume after unsealing, got %d: %s", statusCode, body)
		}
	})
}

func TestStatusReportsSealAndRaftState(t *testing.T) {
	node := &tu.FakeClusterNode{
		NodeID:      2,
		NodeAddress: "10.0.0.2:9000",
		LeaderID:    1,
		MemberList: []cluster.MemberInfo{
			{ID: 1, Address: "10.0.0.1:9000", Role: cluster.RoleVoter},
			{ID: 2, Address: "10.0.0.2:9000", Role: cluster.RoleStandBy},
		},
	}
	ts, sealState := tu.MustPrepareSealedClusterServer(t, node)

	sealed := mustGetSealedStatus(t, ts.URL, ts.Client())
	if !sealed.Data.Sealed {
		t.Fatal("expected the node to report itself sealed")
	}
	if sealed.Data.NodeID != "2" {
		t.Fatalf("expected node ID %q, got %q", "2", sealed.Data.NodeID)
	}
	if sealed.Data.Role != string(cluster.RoleStandBy) {
		t.Fatalf("expected role %q, got %q", cluster.RoleStandBy, sealed.Data.Role)
	}
	if sealed.Data.RaftState != "follower" {
		t.Fatalf("expected raft state %q, got %q", "follower", sealed.Data.RaftState)
	}

	sealState.Unseal()

	unsealed := mustGetSealedStatus(t, ts.URL, ts.Client())
	if unsealed.Data.Sealed {
		t.Fatal("expected the node to report itself unsealed")
	}
}

func TestStatusReportsLeadershipAndUnreachableClusters(t *testing.T) {
	t.Run("leader", func(t *testing.T) {
		node := &tu.FakeClusterNode{
			NodeID:      1,
			NodeAddress: "10.0.0.1:9000",
			LeaderID:    1,
			MemberList: []cluster.MemberInfo{
				{ID: 1, Address: "10.0.0.1:9000", Role: cluster.RoleVoter},
			},
		}
		ts, _ := tu.MustPrepareClusterServer(t, node)

		status := mustGetSealedStatus(t, ts.URL, ts.Client())
		if status.Data.Sealed {
			t.Fatal("expected an unsealed node")
		}
		if status.Data.RaftState != "leader" {
			t.Fatalf("expected raft state %q, got %q", "leader", status.Data.RaftState)
		}
	})

	// /status is what an operator reaches for when the cluster is broken, so it
	// still answers when membership cannot be read.
	t.Run("unreachable cluster", func(t *testing.T) {
		node := &tu.FakeClusterNode{NodeID: 1, NodeAddress: "10.0.0.1:9000", Err: errors.New("no leader available")}
		ts, _ := tu.MustPrepareClusterServer(t, node)

		status := mustGetSealedStatus(t, ts.URL, ts.Client())
		if status.Data.NodeID != "1" {
			t.Fatalf("expected node ID %q, got %q", "1", status.Data.NodeID)
		}
		if status.Data.Role != "" {
			t.Fatalf("expected no role, got %q", status.Data.Role)
		}
		if status.Data.RaftState != "unknown" {
			t.Fatalf("expected raft state %q, got %q", "unknown", status.Data.RaftState)
		}
	})
}

// An unclustered node has no Raft identity to report, and is never sealed for
// long enough to matter: its unwrap happens before it serves anything.
func TestStatusOmitsClusterFieldsWhenClusteringIsDisabled(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)

	status := mustGetSealedStatus(t, ts.URL, ts.Client())
	if status.Data.Sealed {
		t.Fatal("expected an unclustered node to be unsealed")
	}
	if status.Data.NodeID != "" || status.Data.Role != "" || status.Data.RaftState != "" {
		t.Fatalf("expected no cluster fields, got %+v", status.Data)
	}
}

func mustGetSealedStatus(t *testing.T, url string, client *http.Client) sealedStatusResponse {
	t.Helper()

	res, err := client.Get(url + "/status")
	if err != nil {
		t.Fatalf("couldn't get status: %s", err)
	}
	defer res.Body.Close() // nolint: errcheck

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, res.StatusCode)
	}

	var status sealedStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		t.Fatalf("couldn't decode status: %s", err)
	}
	return status
}
