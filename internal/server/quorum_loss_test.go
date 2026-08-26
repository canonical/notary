package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

// Quorum loss — a majority of voters unreachable — is terminal for a dqlite
// cluster: no leader can be elected, and go-dqlite routes every connection
// through the leader, so reads fail alongside writes. spec.md §5 records that as
// the expected final behaviour rather than a gap to close, which makes the
// contract worth pinning: the node must fail cleanly and stay diagnosable, not
// hang, panic, or answer with stale data.
//
// Reproducing a real partition needs several Linux hosts running real dqlite
// nodes, so both halves of the condition are injected here instead: the cluster
// node reports every membership query as unreachable, and the repository the
// handlers query is closed out from under them.
func TestQuorumLossFailsRequestsCleanly(t *testing.T) {
	node := fakeThreeNodeCluster()
	ts, database := tu.MustPrepareClusterServerWithDatabase(t, node)

	// The account has to exist before the cluster goes away; afterwards nothing
	// can be written.
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	createCertificateRequest, err := json.Marshal(tu.CreateCertificateRequestParams{CSR: tu.AppleCSR})
	if err != nil {
		t.Fatalf("couldn't encode the certificate request: %s", err)
	}

	node.Err = errors.New("no leader available")
	// Closing the connection rather than the repository is what makes this a
	// faithful stand-in: the handlers keep their prepared statements, exactly as
	// they would during a partition, and every query they run fails.
	if err := database.Conn.PlainDB().Close(); err != nil {
		t.Fatalf("couldn't close the database connection: %s", err)
	}

	requests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{name: "a read", method: http.MethodGet, path: "/api/v1/certificate_requests"},
		{name: "a write", method: http.MethodPost, path: "/api/v1/certificate_requests", body: createCertificateRequest},
	}
	for _, request := range requests {
		t.Run(request.name+" fails with a server error", func(t *testing.T) {
			statusCode, body := tu.DoClusterAPIRequest(t, ts, request.method, request.path, adminToken, request.body)
			if statusCode < http.StatusInternalServerError {
				t.Fatalf("expected a server error, got %d: %s", statusCode, body)
			}
		})
	}

	// /status is what an operator reaches for when everything else is failing,
	// so it must keep answering and must report what it still knows.
	t.Run("status still reports the node's cluster state", func(t *testing.T) {
		res, err := ts.Client().Get(ts.URL + "/status")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		defer res.Body.Close() // nolint: errcheck

		if res.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, res.StatusCode)
		}

		var status sealedStatusResponse
		if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
			t.Fatalf("couldn't decode status: %s", err)
		}
		if status.Data.NodeID != "1" {
			t.Fatalf("expected node ID %q, got %q", "1", status.Data.NodeID)
		}
		if status.Data.RaftState != "unknown" {
			t.Fatalf("expected raft state %q, got %q", "unknown", status.Data.RaftState)
		}
	})
}
