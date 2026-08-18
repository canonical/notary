package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/canonical/notary/version"
	"go.uber.org/zap"
)

// clusterStatusTimeout bounds the Raft lookups /status makes. The endpoint has
// to answer even when the cluster is unhealthy, so it reports what it knows and
// leaves the rest empty rather than blocking or failing.
const clusterStatusTimeout = 5 * time.Second

// Raft states reported by /status. They describe this node's relationship to the
// current leader, not its configured role.
const (
	raftStateLeader   = "leader"
	raftStateFollower = "follower"
	raftStateNoLeader = "no-leader"
	raftStateUnknown  = "unknown"
)

type StatusResponse struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
	OIDCEnabled bool   `json:"oidc_enabled"`
	// OIDCProviders lists the names of every configured identity provider so the
	// login page can render a selector when more than one is available.
	OIDCProviders []string `json:"oidc_providers,omitempty"`
	// Sealed reports whether this node has unwrapped its data encryption key. A
	// sealed node replicates and votes normally but returns 503 on every route
	// that needs plaintext key material. It unseals itself as soon as its
	// encryption backend is reachable; there is no unseal action.
	Sealed bool `json:"sealed"`
	// NodeID is this node's dqlite node ID, empty when clustering is disabled.
	NodeID string `json:"node_id,omitempty"`
	// Role is this node's configured Raft role: voter, standby or spare.
	Role string `json:"role,omitempty"`
	// RaftState is this node's current relationship to the Raft leader.
	RaftState string `json:"raft_state,omitempty"`
}

// the GET status endpoint returns a http.StatusOK alongside info about the server
// initialized means the first user has been created
func GetStatus(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			// A cluster that has lost quorum serves no reads at all, and /status
			// is exactly what an operator reaches for when that happens. Report
			// everything that can be answered without the database rather than
			// going dark. The 503 is what stops a caller from reading the
			// resulting `initialized: false` as a fresh install.
			env.SystemLogger.Error("failed to generate status", zap.Error(err))
			degraded := StatusResponse{
				Version:       version.GetVersion(),
				OIDCEnabled:   env.AuthnRepository.Enabled(),
				OIDCProviders: env.AuthnRepository.Names(),
				Sealed:        env.EncryptionRepository.Sealed(),
			}
			degraded.NodeID, degraded.Role, degraded.RaftState = nodeClusterStatus(r.Context(), env)
			writeResponse(w, http.StatusServiceUnavailable, "storage is unavailable", degraded, env.SystemLogger)
			return
		}
		statusResponse := StatusResponse{
			Initialized:   numUsers > 0,
			Version:       version.GetVersion(),
			OIDCEnabled:   env.AuthnRepository.Enabled(),
			OIDCProviders: env.AuthnRepository.Names(),
			Sealed:        env.EncryptionRepository.Sealed(),
		}
		statusResponse.NodeID, statusResponse.Role, statusResponse.RaftState = nodeClusterStatus(r.Context(), env)
		writeResponse(w, http.StatusOK, "", statusResponse, env.SystemLogger)
	}
}

// nodeClusterStatus describes this node's place in the Raft cluster. Everything
// is empty when clustering is disabled, and the role and state fall back to
// "unknown" rather than an error when the cluster cannot be reached: /status is
// the endpoint an operator reaches for precisely when things are broken.
func nodeClusterStatus(ctx context.Context, env *HandlerDependencies) (nodeID, role, raftState string) {
	node := env.ClusterNode
	if node == nil {
		return "", "", ""
	}

	id := node.ID()
	nodeID = strconv.FormatUint(id, 10)

	ctx, cancel := context.WithTimeout(ctx, clusterStatusTimeout)
	defer cancel()

	members, err := node.Members(ctx)
	if err != nil {
		env.SystemLogger.Warn("failed to read cluster membership for status", zap.Error(err))
		return nodeID, "", raftStateUnknown
	}
	for _, member := range members {
		if member.ID == id {
			role = string(member.Role)
			break
		}
	}

	leader, err := node.Leader(ctx)
	switch {
	case err != nil:
		env.SystemLogger.Warn("failed to read cluster leader for status", zap.Error(err))
		raftState = raftStateUnknown
	case leader == nil:
		raftState = raftStateNoLeader
	case leader.ID == id:
		raftState = raftStateLeader
	default:
		raftState = raftStateFollower
	}

	return nodeID, role, raftState
}
