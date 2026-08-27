package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	clusterAPIToken      string
	clusterTokenTTL      time.Duration
	clusterTokenQuiet    bool
	clusterTokenIdentity string
	clusterJoinAddress   string
	clusterJoinName      string
	clusterJoinCACert    string
)

// clusterTokenCmd groups the join-token commands.
var clusterTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage cluster join tokens",
}

var clusterTokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a single-use token that lets one node join the cluster",
	Long: `Creates a single-use, time-limited token bound to one joining node's
advertise address. The token is printed once and cannot be retrieved again: only
its hash is stored. Transfer it to the new node out of band. It authorizes
preflight and peer discovery; it does not issue cluster certificates.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		var created server.CreateJoinTokenResponse
		err = client.do("POST", "/cluster/members/tokens", server.CreateJoinTokenParams{
			Identity:   clusterTokenIdentity,
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
	Short: "List cluster members and their state",

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		var status server.ClusterStatusResponse
		if err := client.do("GET", "/cluster/status", nil, &status); err != nil {
			return err
		}

		leader := status.LeaderID
		if leader == "" {
			leader = "none"
		}
		// Everything goes through the tabwriter, which buffers: Flush is where a
		// write error actually surfaces, so the individual writes are ignored.
		writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintf(writer, "Cluster: %d member(s), %d voter(s), leader %s\n\n", len(status.Members), status.Voters, leader)
		_, _ = fmt.Fprintln(writer, "NAME\tURL\tROLES\tSTATE\tMESSAGE")
		for _, member := range status.Members {
			name := member.Name
			if name == "" {
				// The ID is printed for every nameless member so status and
				// acme-issuer still have something to address.
				name = member.ID
			}
			_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
				name, member.Address, clusterMemberRoles(member), member.Status, member.Message)
		}

		return writer.Flush()
	},
}

var clusterACMEIssuerCmd = &cobra.Command{
	Use:   "acme-issuer set <node-id>",
	Short: "Set the designated ACME issuer",
	Long: `Sets which cluster member may run ACME issuance.

Stop or prove the previous issuer dead before running this. Automatic failover
is not supported.`,
	Args: cobra.ExactArgs(2),

	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "set" {
			return fmt.Errorf("unknown acme-issuer command %q, want set", args[0])
		}

		client, err := localClusterAPIClient(cmd)
		if err != nil {
			return err
		}

		var updated server.ACMEIssuerResponse
		if err := client.do("PUT", "/cluster/acme-issuer", server.SetACMEIssuerParams{NodeID: args[1]}, &updated); err != nil {
			return err
		}

		cmd.Printf("ACME issuer set to node %s\n", updated.NodeID)
		return nil
	},
}

var clusterJoinCmd = &cobra.Command{
	Use:   "join <token>",
	Short: "Join this node to an existing cluster",
	Long: `Joins this node to an existing cluster.

This node must already hold operator-provisioned cluster PKI. The join token
runs schema preflight and returns peer addresses; go-dqlite then joins over
mTLS. The private key never leaves this node.

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

		if err := cluster.ParseAdvertiseAddress(clusterJoinAddress); err != nil {
			return fmt.Errorf("existing member --address: %w", err)
		}

		// Checked before anything is written so joining cannot occupy a
		// working member's state directory.
		occupied, err := cluster.HasState(clusterConfig.StateDir)
		if err != nil {
			return err
		}
		if occupied {
			return cluster.ErrAlreadyInitialized
		}
		if _, err := cluster.RequireProvisionedPKI(clusterConfig.StateDir, clusterConfig.Address); err != nil {
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

		var joined server.JoinClusterResponse
		err = client.do("POST", "/cluster/members/join", server.JoinClusterParams{
			Token:         args[0],
			Address:       clusterConfig.Address,
			SchemaVersion: schemaVersion,
		}, &joined)
		if err != nil {
			return err
		}

		peers := excludeAddress(joined.MemberAddress, clusterConfig.Address)
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
		database, err := openClusteredDatabase(ctx, node)
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
		// voters filled and promoting a stand-by when one is lost.
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

// clusterMemberRoles renders a member's Raft role the way `lxc cluster list`
// shows database roles: the leader is named distinctly from the other voters.
func clusterMemberRoles(member server.ClusterMemberResponse) string {
	if member.Leader {
		return "database-leader"
	}
	switch member.Role {
	case "voter":
		return "database-voter"
	case "standby":
		return "database-standby"
	default:
		return member.Role
	}
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
