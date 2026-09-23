package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/canonical/go-dqlite/v3/client"
)

const storeFile = "cluster.yaml"

var memberNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62})$`)

// Member is one dqlite node in the cluster.
type Member struct {
	Name       string `json:"name"`
	ID         uint64 `json:"id"`
	Address    string `json:"address"`
	APIAddress string `json:"api_address,omitempty"`
	Role       string `json:"role"`
	Leader     bool   `json:"leader"`
}

// DefaultMemberName is cluster.name when unset (machine hostname).
func DefaultMemberName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "notary"
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if !ValidMemberName(h) {
		return "notary"
	}
	return h
}

// ValidMemberName reports whether name is usable as a cluster member name.
func ValidMemberName(name string) bool {
	return memberNameRe.MatchString(name)
}

func requireMemberName(name string) error {
	if !ValidMemberName(name) {
		return fmt.Errorf("%w %q", ErrInvalidMemberName, name)
	}
	return nil
}

// Members returns the current cluster membership from a running node.
func (n *Node) Members(ctx context.Context) ([]Member, error) {
	if n == nil || n.app == nil {
		return nil, fmt.Errorf("dqlite node is not running")
	}
	cli, err := n.app.FindLeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("find cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck
	return membersFromClient(ctx, cli)
}

// MembersWithNames is Members plus names from cluster_members.
func (n *Node) MembersWithNames(ctx context.Context, sqldb *sql.DB) ([]Member, error) {
	members, err := n.Members(ctx)
	if err != nil {
		return nil, err
	}
	return attachNames(ctx, sqldb, members)
}

// QueryMembers lists membership by connecting as a client. The Notary daemon
// must be running. dir is db_path; certPEM/keyPEM are the shared cluster TLS
// files (empty for a plaintext single-node).
func QueryMembers(ctx context.Context, dir string, certPEM, keyPEM []byte) ([]Member, error) {
	return QueryMembersTLS(ctx, dir, tlsFromCertKey(certPEM, keyPEM))
}

// QueryMembersTLS lists membership using shared or CA cluster TLS.
func QueryMembersTLS(ctx context.Context, dir string, t TransportTLS) ([]Member, error) {
	cli, err := connectLeader(ctx, dir, t)
	if err != nil {
		return nil, err
	}
	defer cli.Close() //nolint:errcheck
	members, err := membersFromClient(ctx, cli)
	if err != nil {
		return nil, err
	}
	sqldb, err := OpenClientDBTLS(ctx, dir, t)
	if err != nil {
		return nil, err
	}
	defer sqldb.Close() //nolint:errcheck
	return attachNames(ctx, sqldb, members)
}

// IssueJoinToken creates an LXD-style join token for a not-yet-joined member.
func IssueJoinToken(ctx context.Context, dir string, certPEM, keyPEM []byte, name string, apiCert []byte, apiAddresses []string) (string, error) {
	return IssueJoinTokenTLS(ctx, dir, tlsFromCertKey(certPEM, keyPEM), name, apiCert, apiAddresses)
}

// IssueJoinTokenTLS creates a join token using shared or CA cluster TLS.
func IssueJoinTokenTLS(ctx context.Context, dir string, t TransportTLS, name string, apiCert []byte, apiAddresses []string) (string, error) {
	sqldb, err := OpenClientDBTLS(ctx, dir, t)
	if err != nil {
		return "", err
	}
	defer sqldb.Close() //nolint:errcheck
	cli, err := connectLeader(ctx, dir, t)
	if err != nil {
		return "", err
	}
	defer cli.Close() //nolint:errcheck
	members, err := membersFromClient(ctx, cli)
	if err != nil {
		return "", err
	}
	members, err = attachNames(ctx, sqldb, members)
	if err != nil {
		return "", err
	}
	cert, key := presentCertKey(t)
	return issueJoinToken(ctx, sqldb, members, name, cert, key, apiCert, apiAddresses)
}

// IssueJoinTokenOnNode issues a token using a running node and its SQL connection.
func IssueJoinTokenOnNode(ctx context.Context, n *Node, sqldb *sql.DB, name string, certPEM, keyPEM, apiCert []byte, apiAddresses []string) (string, error) {
	members, err := n.MembersWithNames(ctx, sqldb)
	if err != nil {
		return "", err
	}
	return issueJoinToken(ctx, sqldb, members, name, certPEM, keyPEM, apiCert, apiAddresses)
}

func issueJoinToken(ctx context.Context, sqldb *sql.DB, members []Member, name string, certPEM, keyPEM, apiCert []byte, apiAddresses []string) (string, error) {
	if err := requireMemberName(name); err != nil {
		return "", err
	}
	exists, err := memberNameExists(ctx, sqldb, name)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("%w %q", ErrMemberExists, name)
	}
	for _, m := range members {
		if m.Name == name {
			return "", fmt.Errorf("%w %q", ErrMemberExists, name)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return "", fmt.Errorf("cluster TLS is required to create a join token")
	}
	if len(apiCert) == 0 {
		return "", fmt.Errorf("HTTPS certificate is required to create a join token")
	}
	var addresses []string
	for _, a := range apiAddresses {
		if a != "" {
			addresses = append(addresses, a)
		}
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("HTTPS address is required to create a join token")
	}
	if err := requireReachableJoinAddresses(addresses); err != nil {
		return "", err
	}
	fingerprint, err := CertFingerprintPEM(apiCert)
	if err != nil {
		return "", err
	}
	secret, err := newJoinSecret()
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(joinTokenTTL)
	if err := putJoinToken(ctx, sqldb, name, secret, expires); err != nil {
		return "", err
	}
	tok := JoinToken{
		ServerName:  name,
		Fingerprint: fingerprint,
		Addresses:   addresses,
		Secret:      secret,
		ExpiresAt:   expires,
	}
	return encodeJoinToken(tok)
}

// RemoveMember evicts a named member from raft and from cluster_members.
func RemoveMember(ctx context.Context, dir string, certPEM, keyPEM []byte, name string) error {
	return RemoveMemberTLS(ctx, dir, tlsFromCertKey(certPEM, keyPEM), name)
}

// RemoveMemberTLS evicts a member using shared or CA cluster TLS.
func RemoveMemberTLS(ctx context.Context, dir string, t TransportTLS, name string) error {
	sqldb, err := OpenClientDBTLS(ctx, dir, t)
	if err != nil {
		return err
	}
	defer sqldb.Close() //nolint:errcheck
	return removeByName(ctx, func(ctx context.Context) (membershipClient, error) {
		return connectLeader(ctx, dir, t)
	}, sqldb, name)
}

// RemoveMemberOnNode evicts a named member using a running node.
func RemoveMemberOnNode(ctx context.Context, n *Node, sqldb *sql.DB, name string) error {
	if n == nil || n.app == nil {
		return fmt.Errorf("dqlite node is not running")
	}
	return removeByName(ctx, func(ctx context.Context) (membershipClient, error) {
		return n.app.FindLeader(ctx)
	}, sqldb, name)
}

// Use the target's raft identity, not the identity of the API node. Both local
// and remote callers must complete the same handover before eviction.
type membershipClient interface {
	Cluster(context.Context) ([]client.NodeInfo, error)
	Leader(context.Context) (*client.NodeInfo, error)
	Assign(context.Context, uint64, client.NodeRole) error
	Transfer(context.Context, uint64) error
	Remove(context.Context, uint64) error
	Close() error
}

type leaderConnector func(context.Context) (membershipClient, error)

func removeByName(ctx context.Context, connect leaderConnector, sqldb *sql.DB, name string) error {
	if err := requireMemberName(name); err != nil && !strings.Contains(name, ":") {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cli, err := connect(ctx)
	if err != nil {
		return fmt.Errorf("find cluster leader: %w", err)
	}
	defer func() { _ = cli.Close() }()
	members, err := cli.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("list cluster members: %w", err)
	}
	records, err := recordsByAddress(ctx, sqldb)
	if err != nil {
		return fmt.Errorf("load cluster member names: %w", err)
	}
	address := name
	for addr, rec := range records {
		if rec.name == name {
			address = addr
			break
		}
	}
	var target *client.NodeInfo
	for i := range members {
		if members[i].Address == address {
			target = &members[i]
			break
		}
	}
	if target == nil {
		// A previous eviction may have committed even if its response or SQL
		// cleanup failed. Only clean metadata; never evict the remaining member.
		if rec, ok := records[address]; ok {
			return deleteMemberName(ctx, sqldb, rec.name)
		}
		return fmt.Errorf("%w %q", ErrMemberNotFound, name)
	}
	if len(members) <= 1 {
		return ErrLastMember
	}
	leader, err := cli.Leader(ctx)
	if err != nil {
		return fmt.Errorf("find cluster leader: %w", err)
	}
	if leader == nil {
		return fmt.Errorf("cluster has no leader")
	}
	if leader.ID == target.ID {
		// Prefer existing voters, then standbys (already replicating), then
		// spares. Assign waits for the candidate to catch up before promotion.
		var successor *client.NodeInfo
		for _, role := range []client.NodeRole{client.Voter, client.StandBy, client.Spare} {
			for i := range members {
				if members[i].ID != target.ID && members[i].Role == role {
					successor = &members[i]
					break
				}
			}
			if successor != nil {
				break
			}
		}
		if successor == nil {
			return fmt.Errorf("no eligible successor for %q", name)
		}
		if successor.Role != client.Voter {
			if err := cli.Assign(ctx, successor.ID, client.Voter); err != nil {
				return fmt.Errorf("promote cluster member %q: %w", successor.Address, err)
			}
		}
		if err := cli.Transfer(ctx, successor.ID); err != nil {
			return fmt.Errorf("transfer cluster leadership: %w", err)
		}
		next, err := connect(ctx)
		if err != nil {
			return fmt.Errorf("find new cluster leader: %w", err)
		}
		_ = cli.Close()
		cli = next
		leader, err = cli.Leader(ctx)
		if err != nil {
			return fmt.Errorf("verify new cluster leader: %w", err)
		}
		if leader == nil || leader.ID == target.ID {
			return fmt.Errorf("cluster leadership did not move away from %q", name)
		}
	}
	if err := cli.Remove(ctx, target.ID); err != nil {
		// Leave the name intact so a retry can reconcile an ambiguous result.
		return fmt.Errorf("remove cluster member %q: %w", name, err)
	}
	if rec, ok := records[address]; ok {
		if err := deleteMemberName(ctx, sqldb, rec.name); err != nil {
			return fmt.Errorf("removed %q from raft but not from cluster_members: %w", rec.name, err)
		}
	}
	return nil
}

func membersFromClient(ctx context.Context, cli *client.Client) ([]Member, error) {
	nodes, err := cli.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cluster members: %w", err)
	}
	leader, err := cli.Leader(ctx)
	if err != nil {
		return nil, fmt.Errorf("find cluster leader: %w", err)
	}
	var leaderAddr string
	if leader != nil {
		leaderAddr = leader.Address
	}
	members := make([]Member, len(nodes))
	for i, node := range nodes {
		members[i] = Member{
			ID:      node.ID,
			Address: node.Address,
			Role:    node.Role.String(),
			Leader:  node.Address == leaderAddr,
		}
	}
	return members, nil
}

func attachNames(ctx context.Context, sqldb *sql.DB, members []Member) ([]Member, error) {
	if sqldb == nil {
		return members, nil
	}
	records, err := recordsByAddress(ctx, sqldb)
	if err != nil {
		if strings.Contains(err.Error(), "no such table: cluster_members") {
			return members, nil
		}
		return nil, fmt.Errorf("load cluster member names: %w", err)
	}
	for i := range members {
		if rec, ok := records[members[i].Address]; ok {
			members[i].Name = rec.name
			members[i].APIAddress = rec.apiAddress
		}
	}
	return members, nil
}

// RegisterMember records this node's name and HTTPS API address after start or join.
func RegisterMember(ctx context.Context, sqldb *sql.DB, name, address, apiAddress string) error {
	if err := requireMemberName(name); err != nil {
		return err
	}
	if address == "" {
		return fmt.Errorf("cluster address is required")
	}
	return upsertMember(ctx, sqldb, name, address, apiAddress)
}

// PruneMembers drops cluster_members rows for addresses raft no longer knows.
// Raft only loses a member through an explicit remove or a recovery, so a row
// without a matching raft entry is stale and would block reusing that name.
func PruneMembers(ctx context.Context, n *Node, sqldb *sql.DB) error {
	if n == nil || n.app == nil || sqldb == nil {
		return nil
	}
	members, err := n.Members(ctx)
	if err != nil {
		return err
	}
	live := make(map[string]struct{}, len(members))
	for _, m := range members {
		live[m.Address] = struct{}{}
	}
	if len(live) == 0 {
		return nil
	}
	return deleteMembersNotIn(ctx, sqldb, live)
}

// ConsumeJoinToken validates and deletes a one-time join token.
func ConsumeJoinToken(ctx context.Context, sqldb *sql.DB, token JoinToken) error {
	return consumeJoinToken(ctx, sqldb, token.ServerName, token.Secret)
}
