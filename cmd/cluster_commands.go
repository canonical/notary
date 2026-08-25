package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	clusterAPIToken    string
	clusterTokenTTL    time.Duration
	clusterTokenQuiet  bool
	clusterRemoveForce bool
	clusterJoinAddress string
	clusterJoinName    string
	clusterJoinCACert  string
)

// clusterMemberView mirrors the member representation the admin API returns.
type clusterMemberView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Role     string `json:"role"`
	Leader   bool   `json:"leader"`
	Sealed   bool   `json:"sealed"`
	LastSeen int64  `json:"last_seen"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type clusterStatusView struct {
	Enabled  bool                `json:"enabled"`
	NodeID   string              `json:"node_id"`
	Address  string              `json:"address"`
	LeaderID string              `json:"leader_id"`
	Voters   int                 `json:"voters"`
	Members  []clusterMemberView `json:"members"`
}

type createJoinTokenRequest struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

type createJoinTokenView struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type joinClusterRequest struct {
	Token         string `json:"token"`
	Address       string `json:"address"`
	CSR           string `json:"csr"`
	SchemaVersion int64  `json:"schema_version"`
}

type joinClusterView struct {
	Certificate     string   `json:"certificate"`
	CACertificate   string   `json:"ca_certificate"`
	MemberAddresses []string `json:"member_addresses"`
}

// clusterTokenCmd groups the join-token commands.
var clusterTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage cluster join tokens",
}

var clusterTokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a single-use token that lets one node join the cluster",
	Long: `Creates a single-use, time-limited token authorizing one node to join the
cluster. The token is printed once and cannot be retrieved again: only its hash
is stored. Transfer it to the new node out of band.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		var created createJoinTokenView
		err = client.do("POST", "/cluster/members/tokens", createJoinTokenRequest{
			TTLSeconds: int64(clusterTokenTTL.Seconds()),
		}, &created)
		if err != nil {
			return err
		}

		if clusterTokenQuiet {
			// cmd.Println writes to stderr; --quiet exists to be captured by a shell.
			_, err := fmt.Fprintln(cmd.OutOrStdout(), created.Token)
			return err
		}

		address := client.advertised
		if address == "" {
			address = "member.example.com:3000"
		}

		// Flags first and the token last after --, so a token is never read as a
		// flag. Tokens this version issues never start with '-', but one issued
		// by an older node can still be within its lifetime.
		cmd.Printf("Join token (shown once, expires %s):\n\n  %s\n\nOn the new node, run:\n\n  notary cluster join --config /path/to/notary.yaml --address %s --ca-cert /path/to/api.crt -- %s\n",
			time.Unix(created.ExpiresAt, 0).UTC().Format(time.RFC3339), created.Token, address, created.Token)

		return nil
	},
}

var clusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the role, leader and seal state of every cluster member",

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		var status clusterStatusView
		if err := client.do("GET", "/cluster/status", nil, &status); err != nil {
			return err
		}

		leader := status.LeaderID
		if leader == "" {
			leader = "none (no leader elected)"
		}
		// Everything goes through the tabwriter, which buffers: Flush is where a
		// write error actually surfaces, so the individual writes are ignored.
		writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintf(writer, "Cluster: %d member(s), %d voter(s), leader %s\n\n", len(status.Members), status.Voters, leader)
		_, _ = fmt.Fprintln(writer, "NAME\tID\tADDRESS\tROLE\tLEADER\tSEALED\tSTATE\tMESSAGE")
		for _, member := range status.Members {
			name := member.Name
			if name == "" {
				// The ID is printed for every member so that one whose name was
				// never recorded is still addressable by promote and remove.
				name = "-"
			}
			_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%t\t%t\t%s\t%s\n",
				name, member.ID, member.Address, member.Role, member.Leader, member.Sealed, member.Status, member.Message)
		}

		return writer.Flush()
	},
}

var clusterPromoteCmd = &cobra.Command{
	Use:   "promote <member>",
	Short: "Promote a member to voter",
	Long: `Promotes a member to voter immediately.

Role convergence is otherwise automatic: dqlite promotes a stand-by on its own
when a voter is permanently removed. This command exists to force that ahead of
the automatic adjustment interval.

<member> is the name recorded when the member joined, or its dqlite node ID.`,
	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		member, err := resolveClusterMember(client, args[0])
		if err != nil {
			return err
		}

		if err := client.do("POST", "/cluster/members/"+escapePathSegment(member.ID)+"/promote", nil, nil); err != nil {
			return err
		}

		cmd.Printf("promoted %s to voter\n", args[0])

		return nil
	},
}

var clusterRemoveCmd = &cobra.Command{
	Use:   "remove <member>",
	Short: "Remove a member from the cluster",
	Long: `Removes a member from the cluster.

<member> is the name recorded when the member joined, or its dqlite node ID.

The member's Raft responsibilities are handed over before it is removed, so a
running member leaves without forcing an election. Use --force for a member that
is already gone, where the handover cannot succeed.`,
	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		member, err := resolveClusterMember(client, args[0])
		if err != nil {
			return err
		}

		path := "/cluster/members/" + escapePathSegment(member.ID)
		if clusterRemoveForce {
			path += "?force=true"
		}
		if err := client.do("DELETE", path, nil, nil); err != nil {
			return err
		}

		cmd.Printf("removed %s from the cluster\n", args[0])

		return nil
	},
}

var clusterJoinCmd = &cobra.Command{
	Use:   "join <token>",
	Short: "Join this node to an existing cluster",
	Long: `Joins this node to an existing cluster.

This node generates its own key pair and certificate signing request, presents
them with the join token to an existing member, and starts replicating once that
member signs the request. The private key never leaves this node.

Run this once, on the new node, before starting the Notary server on it.`,
	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := config.ParseConfig(cmd.Flags(), clusterConfigFilePath)
		if err != nil {
			return fmt.Errorf("couldn't parse and validate config: %w", err)
		}
		if !appConfig.ClusterConfig.Enabled {
			return errors.New("clustering is not enabled: set `cluster.enabled` to true in the config file")
		}

		clusterConfig := appConfig.ClusterConfig
		csrPEM, err := cluster.PrepareJoin(clusterConfig.StateDir, clusterConfig.Address)
		if err != nil {
			return err
		}

		client, err := newJoinAPIClient(clusterJoinAddress, clusterJoinCACert)
		if err != nil {
			return err
		}

		schemaVersion, err := db.EmbeddedSchemaVersion()
		if err != nil {
			return err
		}

		var signed joinClusterView
		err = client.do("POST", "/cluster/members/join", joinClusterRequest{
			Token:         args[0],
			Address:       clusterConfig.Address,
			CSR:           string(csrPEM),
			SchemaVersion: schemaVersion,
		}, &signed)
		if err != nil {
			return err
		}

		if err := cluster.CompleteJoin(clusterConfig.StateDir, []byte(signed.Certificate), []byte(signed.CACertificate)); err != nil {
			return err
		}

		peers := excludeAddress(signed.MemberAddresses, clusterConfig.Address)
		if len(peers) == 0 {
			return errors.New("the existing member reported no cluster addresses to join")
		}

		node, err := cluster.Start(cluster.Options{
			StateDir: clusterConfig.StateDir,
			Address:  clusterConfig.Address,
			Join:     peers,
		})
		if err != nil {
			return fmt.Errorf("couldn't join the cluster: %w", err)
		}
		defer closeClusterNode(node, zap.L())

		ctx, cancel := context.WithTimeout(cmd.Context(), clusterReadyTimeout)
		defer cancel()

		// Migrations are never applied here: the cluster this node is joining
		// already has the schema, and it arrives through replication.
		database, err := openClusteredDatabase(ctx, node, false)
		if err != nil {
			return err
		}
		defer database.Close() //nolint:errcheck

		name := clusterJoinName
		if name == "" {
			name = clusterConfig.Address
		}
		nodeID := formatNodeID(node.ID())

		// The node is in the cluster by this point. A missing name record is
		// cosmetic and must not be reported as a failed join: the join cannot be
		// retried, and treating it as failure would send an operator looking for a
		// member to clean up that is in fact healthy.
		if _, err := database.CreateClusterMember(nodeID, name, clusterConfig.Address, time.Now().UTC()); err != nil {
			cmd.Printf("joined the cluster as node %s, but couldn't record the name %q: %s\n", nodeID, name, err)
			cmd.Printf("the member is in the cluster and will show without a name; address it by its ID in `notary cluster status`\n")
			return nil
		}

		// dqlite assigns Raft roles itself, keeping the configured number of
		// voters filled and promoting a stand-by when one is lost. `notary cluster
		// promote` forces it ahead of that.
		cmd.Printf("joined the cluster as %s (node %s)\n", name, nodeID)

		return nil
	},
}

// localClusterAPIClient builds an API client for the node described by the
// --config file, taking the admin token from --token or the environment.
func localClusterAPIClient(cmd *cobra.Command) (*apiClient, error) {
	appConfig, err := config.ParseConfig(cmd.Flags(), clusterConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse and validate config: %w", err)
	}

	token := clusterAPIToken
	if token == "" {
		token = os.Getenv(apiTokenEnvVar)
	}

	return newLocalAPIClient(appConfig, token)
}

// formatNodeID renders a dqlite node ID the way it is stored and displayed. It
// is a uint64, so it never goes through an int64.
func formatNodeID(id uint64) string {
	return strconv.FormatUint(id, 10)
}

// resolveClusterMember accepts either the name recorded for a member or its raw
// dqlite node ID, so operators are never forced to handle node IDs.
func resolveClusterMember(client *apiClient, identifier string) (*clusterMemberView, error) {
	var members []clusterMemberView
	if err := client.do("GET", "/cluster/members", nil, &members); err != nil {
		return nil, err
	}

	for i := range members {
		if members[i].ID == identifier || members[i].Name == identifier {
			return &members[i], nil
		}
	}

	known := make([]string, 0, len(members))
	for _, member := range members {
		if member.Name != "" {
			known = append(known, member.Name)
			continue
		}
		known = append(known, member.ID)
	}

	return nil, fmt.Errorf("no cluster member named %q; known members: %s", identifier, strings.Join(known, ", "))
}

// excludeAddress drops this node's own address from the peer list an existing
// member reported, which matters when rejoining an address the cluster still
// remembers.
func excludeAddress(addresses []string, own string) []string {
	peers := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address != own {
			peers = append(peers, address)
		}
	}
	return peers
}
