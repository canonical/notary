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
	Name    string `json:"name"`
	ID      uint64 `json:"id"`
	Address string `json:"address"`
	Role    string `json:"role"`
	Leader  bool   `json:"leader"`
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
	cli, err := connectLeader(ctx, dir, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	defer cli.Close() //nolint:errcheck
	members, err := membersFromClient(ctx, cli)
	if err != nil {
		return nil, err
	}
	sqldb, err := OpenClientDB(ctx, dir, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	defer sqldb.Close() //nolint:errcheck
	return attachNames(ctx, sqldb, members)
}

// IssueJoinToken creates an LXD-style join token for a not-yet-joined member.
func IssueJoinToken(ctx context.Context, dir string, certPEM, keyPEM []byte, name string, apiCert []byte, apiAddresses []string) (string, error) {
	sqldb, err := OpenClientDB(ctx, dir, certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	defer sqldb.Close() //nolint:errcheck
	cli, err := connectLeader(ctx, dir, certPEM, keyPEM)
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
	return issueJoinToken(ctx, sqldb, members, name, certPEM, keyPEM, apiCert, apiAddresses)
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
	return encodeJoinToken(JoinToken{
		ServerName:  name,
		Fingerprint: fingerprint,
		Addresses:   addresses,
		Secret:      secret,
		ExpiresAt:   expires,
	})
}

// RemoveMember evicts a named member from raft and from cluster_members.
func RemoveMember(ctx context.Context, dir string, certPEM, keyPEM []byte, name string) error {
	cli, err := connectLeader(ctx, dir, certPEM, keyPEM)
	if err != nil {
		return err
	}
	defer cli.Close() //nolint:errcheck
	sqldb, err := OpenClientDB(ctx, dir, certPEM, keyPEM)
	if err != nil {
		return err
	}
	defer sqldb.Close() //nolint:errcheck
	members, err := membersFromClient(ctx, cli)
	if err != nil {
		return err
	}
	members, err = attachNames(ctx, sqldb, members)
	if err != nil {
		return err
	}
	return removeByName(ctx, cli, sqldb, members, name)
}

// RemoveMemberOnNode evicts a named member using a running node.
func RemoveMemberOnNode(ctx context.Context, n *Node, sqldb *sql.DB, name string) error {
	if n == nil || n.app == nil {
		return fmt.Errorf("dqlite node is not running")
	}
	cli, err := n.app.FindLeader(ctx)
	if err != nil {
		return fmt.Errorf("find cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck
	members, err := n.MembersWithNames(ctx, sqldb)
	if err != nil {
		return err
	}
	return removeByName(ctx, cli, sqldb, members, name)
}

func removeByName(ctx context.Context, cli *client.Client, sqldb *sql.DB, members []Member, name string) error {
	if err := requireMemberName(name); err != nil && !strings.Contains(name, ":") {
		return err
	}
	if len(members) <= 1 {
		return ErrLastMember
	}
	var target *Member
	for i := range members {
		if members[i].Name == name || members[i].Address == name {
			target = &members[i]
			break
		}
	}
	if target == nil {
		addr, err := addressForName(ctx, sqldb, name)
		if err == nil {
			for i := range members {
				if members[i].Address == addr {
					target = &members[i]
					break
				}
			}
		}
	}
	if target == nil {
		return fmt.Errorf("%w %q", ErrMemberNotFound, name)
	}
	if err := cli.Remove(ctx, target.ID); err != nil {
		return fmt.Errorf("remove cluster member %q: %w", name, err)
	}
	if target.Name != "" {
		if err := deleteMemberName(ctx, sqldb, target.Name); err != nil {
			return fmt.Errorf("removed %q from raft but not from cluster_members: %w", target.Name, err)
		}
	}
	if name != target.Name {
		if err := deleteMemberName(ctx, sqldb, name); err != nil {
			return fmt.Errorf("removed %q from raft but not from cluster_members: %w", name, err)
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
	names, err := namesByAddress(ctx, sqldb)
	if err != nil {
		if strings.Contains(err.Error(), "no such table: cluster_members") {
			return members, nil
		}
		return nil, fmt.Errorf("load cluster member names: %w", err)
	}
	for i := range members {
		if n, ok := names[members[i].Address]; ok {
			members[i].Name = n
		}
	}
	return members, nil
}

// RegisterMember records this node's name after start or join.
func RegisterMember(ctx context.Context, sqldb *sql.DB, name, address string) error {
	if err := requireMemberName(name); err != nil {
		return err
	}
	if address == "" {
		return fmt.Errorf("cluster address is required")
	}
	return upsertMember(ctx, sqldb, name, address)
}

// ConsumeJoinToken validates and deletes a one-time join token.
func ConsumeJoinToken(ctx context.Context, sqldb *sql.DB, token JoinToken) error {
	return consumeJoinToken(ctx, sqldb, token.ServerName, token.Secret)
}
