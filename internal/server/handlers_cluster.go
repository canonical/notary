package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// defaultJoinTokenTTL is how long a join token stays valid when the caller does
// not say. Join tokens are transferred out of band, so the window is kept short:
// long enough for an operator to paste it into a provisioning step, not long
// enough to sit forgotten in a shell history.
const defaultJoinTokenTTL = time.Hour

// maxJoinTokenTTL bounds what an operator may ask for. A join token is on its
// own sufficient to obtain a cluster certificate, so it must never be a
// long-lived credential (spec §1.2).
const maxJoinTokenTTL = 24 * time.Hour

type ClusterMemberResponse struct {
	// ID is the dqlite node ID as a decimal string; it does not fit an int64.
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Role    string `json:"role"`
	Leader  bool   `json:"leader"`
	// Sealed is the member's own last report of whether it has unwrapped its
	// encryption key. It is only meaningful while the member is online.
	Sealed bool `json:"sealed"`
	// LastSeen is the member's last heartbeat in Unix seconds, or 0 if it has
	// never reported one.
	LastSeen int64 `json:"last_seen"`
	// Status is ONLINE or OFFLINE, derived from LastSeen.
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Member status values, and the messages that go with them, follow `lxc cluster
// list` so that an operator familiar with LXD reads the same table here.
const (
	MemberStatusOnline  = "ONLINE"
	MemberStatusOffline = "OFFLINE"

	memberMessageOperational = "Fully operational"
	memberMessageSealed      = "Sealed, waiting to unwrap its encryption key"
	memberMessageNeverSeen   = "Has never reported a heartbeat"
)

type ClusterStatusResponse struct {
	Enabled bool   `json:"enabled"`
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	// LeaderID is empty while the cluster has no leader, which is what a client
	// sees during an election or a quorum loss.
	LeaderID string                  `json:"leader_id"`
	Voters   int                     `json:"voters"`
	Members  []ClusterMemberResponse `json:"members"`
}

type CreateJoinTokenParams struct {
	// Identity is the joining node's advertise address. The token is bound to it.
	Identity string `json:"identity"`
	// TTLSeconds bounds the token's lifetime. Empty means defaultJoinTokenTTL.
	TTLSeconds int64 `json:"ttl_seconds"`
}

type CreateJoinTokenResponse struct {
	// Token is returned exactly once, here. Only its hash is stored.
	Token     string `json:"token"`
	Identity  string `json:"identity"`
	ExpiresAt int64  `json:"expires_at"`
}

type JoinClusterParams struct {
	Token string `json:"token"`
	// Address is the address the joining node will advertise to its peers. It
	// must match the identity the token was issued for.
	Address string `json:"address"`
	// SchemaVersion is the migration version the joining node is built for. A
	// node whose schema differs from the cluster's is refused (spec §4.1).
	SchemaVersion int64 `json:"schema_version"`
}

type JoinClusterResponse struct {
	MemberAddress []string `json:"member_addresses"`
}

type SetACMEIssuerParams struct {
	NodeID string `json:"node_id"`
}

type ACMEIssuerResponse struct {
	NodeID string `json:"node_id"`
}

// clusterEnabled reports whether the cluster API can serve this request, writing
// the error response itself when it cannot.
func clusterEnabled(w http.ResponseWriter, env *HandlerDependencies) bool {
	if env.ClusterNode == nil {
		writeResponse(w, http.StatusNotFound, "clustering is not enabled", nil, env.SystemLogger)
		return false
	}
	return true
}

// ListClusterMembers reports every dqlite member, joined with the
// operator-assigned names Notary stores for them.
func ListClusterMembers(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		members, err := collectClusterMembers(r, env)
		if err != nil {
			env.SystemLogger.Error("failed to list cluster members", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to list cluster members", nil, env.SystemLogger)
			return
		}

		writeResponse(w, http.StatusOK, "", members, env.SystemLogger)
	}
}

// GetClusterStatus reports the cluster's aggregate health from this node's point
// of view.
func GetClusterStatus(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		members, err := collectClusterMembers(r, env)
		if err != nil {
			env.SystemLogger.Error("failed to read cluster status", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to read cluster status", nil, env.SystemLogger)
			return
		}

		status := ClusterStatusResponse{
			Enabled: true,
			NodeID:  strconv.FormatUint(env.ClusterNode.ID(), 10),
			Address: env.ClusterNode.Address(),
			Members: members,
		}
		for _, member := range members {
			if member.Role == string(cluster.RoleVoter) {
				status.Voters++
			}
			if member.Leader {
				status.LeaderID = member.ID
			}
		}

		writeResponse(w, http.StatusOK, "", status, env.SystemLogger)
	}
}

// CreateClusterJoinToken issues a single-use join token. The token is returned
// once and never again: only its hash is stored.
func CreateClusterJoinToken(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		var params CreateJoinTokenParams
		// An empty body is valid: it asks for a token with the default TTL.
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil && !errors.Is(err, io.EOF) {
			writeResponse(w, http.StatusBadRequest, "invalid request body", nil, env.SystemLogger)
			return
		}

		if params.Identity == "" {
			writeResponse(w, http.StatusBadRequest, "identity is required", nil, env.SystemLogger)
			return
		}
		if err := cluster.ParseAdvertiseAddress(params.Identity); err != nil {
			writeResponse(w, http.StatusBadRequest, "identity must be host:port, not a URL", nil, env.SystemLogger)
			return
		}

		ttl := defaultJoinTokenTTL
		if params.TTLSeconds != 0 {
			ttl = time.Duration(params.TTLSeconds) * time.Second
		}
		if ttl <= 0 || ttl > maxJoinTokenTTL {
			writeResponse(w, http.StatusBadRequest, "ttl_seconds must be between 1 second and 24 hours", nil, env.SystemLogger)
			return
		}

		token, hash, err := cluster.GenerateJoinToken()
		if err != nil {
			env.SystemLogger.Error("failed to generate cluster join token", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to create join token", nil, env.SystemLogger)
			return
		}

		now := time.Now().UTC()
		expiresAt := now.Add(ttl)
		if _, err := env.Database.CreateClusterJoinToken(hash, params.Identity, now, expiresAt); err != nil {
			env.SystemLogger.Error("failed to store cluster join token", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to create join token", nil, env.SystemLogger)
			return
		}

		writeResponse(w, http.StatusCreated, "", CreateJoinTokenResponse{
			Token:     token,
			Identity:  params.Identity,
			ExpiresAt: expiresAt.Unix(),
		}, env.SystemLogger)
	}
}

// JoinCluster runs schema preflight and returns peer addresses in exchange for
// a valid, identity-bound bootstrap token. It does not issue certificates.
//
// This endpoint is deliberately not behind session authentication: a node that
// has not joined yet has no account. The token is the preflight credential.
func JoinCluster(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		var params JoinClusterParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid request body", nil, env.SystemLogger)
			return
		}
		if params.Token == "" || params.Address == "" {
			writeResponse(w, http.StatusBadRequest, "token and address are required", nil, env.SystemLogger)
			return
		}
		if err := cluster.ParseAdvertiseAddress(params.Address); err != nil {
			writeResponse(w, http.StatusBadRequest, "address must be host:port, not a URL", nil, env.SystemLogger)
			return
		}

		tokenHash := cluster.HashJoinToken(params.Token)
		now := time.Now().UTC()
		if writeInvalidJoinToken(w, env, env.Database.VerifyClusterJoinToken(tokenHash, params.Address, now), params.Address) {
			return
		}

		if err := env.Database.CheckSchemaVersion(params.SchemaVersion); err != nil {
			if errors.Is(err, db.ErrSchemaVersionMismatch) {
				env.SystemLogger.Warn("rejected cluster join with a mismatched schema version",
					zap.String("address", params.Address), zap.Error(err))
				writeResponse(w, http.StatusConflict, err.Error(), nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to compare schema versions", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to process join request", nil, env.SystemLogger)
			return
		}

		members, err := env.ClusterNode.Members(r.Context())
		if err != nil {
			env.SystemLogger.Error("failed to list cluster members", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to process join request", nil, env.SystemLogger)
			return
		}
		addresses := make([]string, 0, len(members))
		for _, member := range members {
			addresses = append(addresses, member.Address)
		}

		if writeInvalidJoinToken(w, env, env.Database.RedeemClusterJoinToken(tokenHash, params.Address, now), params.Address) {
			return
		}

		env.SystemLogger.Info("admitted a cluster join preflight", zap.String("address", params.Address))

		writeResponse(w, http.StatusOK, "", JoinClusterResponse{
			MemberAddress: addresses,
		}, env.SystemLogger)
	}
}

// SetACMEIssuer records which member may run ACME issuance. The previous issuer
// must already be stopped; this handler does not fence a live process.
func SetACMEIssuer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		var params SetACMEIssuerParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid request body", nil, env.SystemLogger)
			return
		}
		if params.NodeID == "" {
			writeResponse(w, http.StatusBadRequest, "node_id is required", nil, env.SystemLogger)
			return
		}

		if _, err := env.Database.GetClusterMember(params.NodeID); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "cluster member not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to look up ACME issuer member", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to set ACME issuer", nil, env.SystemLogger)
			return
		}

		if err := env.Database.SetACMEIssuerNodeID(params.NodeID); err != nil {
			env.SystemLogger.Error("failed to set ACME issuer", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "failed to set ACME issuer", nil, env.SystemLogger)
			return
		}

		writeResponse(w, http.StatusOK, "", ACMEIssuerResponse{NodeID: params.NodeID}, env.SystemLogger)
	}
}

// DeleteClusterMember rejects removal until cluster credentials can be revoked.
// Removing only the Raft member leaves its CA-signed certificate trusted, and
// every admitted member has had access to the replicated CA signing key.
func DeleteClusterMember(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !clusterEnabled(w, env) {
			return
		}

		writeResponse(w, http.StatusNotImplemented,
			"cluster member removal is disabled because dqlite does not revoke the member's certificate; isolate the host, rotate cluster trust, and rebuild retained members",
			nil, env.SystemLogger)
	}
}

// collectClusterMembers merges dqlite's view of the cluster with the names
// Notary recorded, and marks the current leader.
func collectClusterMembers(r *http.Request, env *HandlerDependencies) ([]ClusterMemberResponse, error) {
	members, err := env.ClusterNode.Members(r.Context())
	if err != nil {
		return nil, err
	}

	// A missing name record is not an error: the member is in the cluster
	// either way, and reporting it namelessly is more useful than failing.
	records := map[string]db.ClusterMember{}
	if rows, err := env.Database.ListClusterMembers(); err != nil {
		env.SystemLogger.Warn("failed to read cluster member records", zap.Error(err))
	} else {
		for _, record := range rows {
			records[record.NodeID] = record
		}
	}

	var leaderID uint64
	if leader, err := env.ClusterNode.Leader(r.Context()); err != nil {
		env.SystemLogger.Warn("failed to identify the cluster leader", zap.Error(err))
	} else if leader != nil {
		leaderID = leader.ID
	}

	now := time.Now().UTC()
	response := make([]ClusterMemberResponse, 0, len(members))
	for _, member := range members {
		id := strconv.FormatUint(member.ID, 10)
		record := records[id]
		entry := ClusterMemberResponse{
			ID:      id,
			Name:    record.Name,
			Address: member.Address,
			Role:    string(member.Role),
			Leader:  leaderID != 0 && member.ID == leaderID,
			Sealed:  record.Sealed,
		}
		if record.Heartbeat != nil {
			entry.LastSeen = *record.Heartbeat
		}
		entry.Status, entry.Message = memberHealth(record, now)
		response = append(response, entry)
	}

	return response, nil
}

// memberHealth turns a member's last heartbeat into the status and message pair
// an operator reads, in the shape `lxc cluster list` uses.
func memberHealth(record db.ClusterMember, now time.Time) (status, message string) {
	if !record.Online(now) {
		if record.Heartbeat == nil {
			return MemberStatusOffline, memberMessageNeverSeen
		}
		last := time.Unix(*record.Heartbeat, 0).UTC()
		return MemberStatusOffline, fmt.Sprintf("No heartbeat since %s", last.Format(time.RFC3339))
	}
	if record.Sealed {
		return MemberStatusOnline, memberMessageSealed
	}

	return MemberStatusOnline, memberMessageOperational
}

// writeInvalidJoinToken reports an invalid or unusable join token. Unknown,
// expired and already-used tokens are the same 401 so a caller learns nothing
// about which tokens exist.
func writeInvalidJoinToken(w http.ResponseWriter, env *HandlerDependencies, err error, address string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, db.ErrNotFound) {
		env.SystemLogger.Warn("rejected cluster join with an invalid token", zap.String("address", address))
		writeResponse(w, http.StatusUnauthorized, "invalid or expired join token", nil, env.SystemLogger)
		return true
	}
	env.SystemLogger.Error("failed to process join token", zap.Error(err))
	writeResponse(w, http.StatusInternalServerError, "failed to process join request", nil, env.SystemLogger)
	return true
}
