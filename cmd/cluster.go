package cmd

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/spf13/cobra"
)

var clusterConfigPath string

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage the Notary cluster",
}

var clusterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cluster members",
	Long: `List cluster members (name, dqlite address, HTTPS API address, role, leader).

The Notary daemon must be running. This command reads cluster.yaml from db_path
and connects as a client; it does not start a second node.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := parseClusterConfig()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		members, err := cluster.QueryMembers(ctx, appConfig.DBPath, appConfig.ClusterTLSCertificate, appConfig.ClusterTLSPrivateKey)
		if err != nil {
			return err
		}
		return writeMemberTable(cmd.OutOrStdout(), members)
	},
}

var clusterAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Create a join token for a new cluster member",
	Long: `Create a one-time join token for a new member, like lxc cluster add.

On an existing node (daemon running):

  notary cluster add node2 --config /path/to/config.yaml

On the new machine, set cluster.name and cluster.address, then start with the token:

  notary start --config /path/to/config.yaml --join <token>
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := parseClusterConfig()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		apiAddr, err := cluster.JoinAPIAddress(appConfig.ClusterAddress, appConfig.Port, appConfig.ExternalHostname)
		if err != nil {
			return err
		}
		token, err := cluster.IssueJoinToken(ctx, appConfig.DBPath, appConfig.ClusterTLSCertificate, appConfig.ClusterTLSPrivateKey, args[0], appConfig.TLSCertificate, []string{apiAddr})
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Member %s join token:\n%s\n", args[0], token) //nolint:errcheck
		return nil
	},
}

var clusterRemoveCmd = &cobra.Command{
	Use:   "remove <name|address>",
	Short: "Remove a cluster member",
	Long: `Remove a named member from the cluster, like lxc cluster remove.

The daemon must be running. This evicts the node from dqlite; stop that
machine's Notary process afterwards. If a join failed after dqlite added
the node, the member may have no name; pass its address instead.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := parseClusterConfig()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := cluster.RemoveMember(ctx, appConfig.DBPath, appConfig.ClusterTLSCertificate, appConfig.ClusterTLSPrivateKey, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Member %s removed\n", args[0]) //nolint:errcheck
		return nil
	},
}

var clusterRecoverForce bool

var clusterRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Force this node into a single-member cluster after quorum loss",
	Long: `Recover a cluster that can no longer elect a leader, like lxd cluster
recover-from-quorum-loss.

Stop Notary on every member first. Run this on the survivor whose raft log is
furthest ahead; without --force the command only reports that log position so
you can compare members. Rejoin the other machines afterwards with a fresh
'notary cluster add' token and an empty db_path.

This is destructive: writes the lost majority committed but never replicated to
this node are discarded.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := parseClusterConfig()
		if err != nil {
			return err
		}
		last, err := cluster.ReadLastEntry(appConfig.DBPath)
		if err != nil {
			return err
		}
		if !clusterRecoverForce {
			fmt.Fprintf(cmd.OutOrStdout(), "Raft log for %s: %s\nRun the same command with --force on the member with the highest term, then index.\n", appConfig.DBPath, last) //nolint:errcheck
			return nil
		}
		info, err := cluster.RecoverToSelf(appConfig.DBPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Recovered %s as the only member (%s, %s).\nStart Notary, then rejoin other machines with 'notary cluster add'.\n", appConfig.DBPath, info.Address, last) //nolint:errcheck
		return nil
	},
}

func parseClusterConfig() (*config.AppConfig, error) {
	appConfig, err := config.ParseConfig(clusterCmd.PersistentFlags(), clusterConfigPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse config: %w", err)
	}
	if len(appConfig.ClusterTLSCertificate) == 0 {
		cert, key, err := cluster.LoadClusterTLS(appConfig.DBPath)
		if err == nil {
			appConfig.ClusterTLSCertificate = cert
			appConfig.ClusterTLSPrivateKey = key
		}
	}
	return appConfig, nil
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(clusterListCmd)
	clusterCmd.AddCommand(clusterAddCmd)
	clusterCmd.AddCommand(clusterRemoveCmd)
	clusterCmd.AddCommand(clusterRecoverCmd)
	clusterRecoverCmd.Flags().BoolVar(&clusterRecoverForce, "force", false, "rewrite membership instead of only reporting the raft log position")
	clusterCmd.PersistentFlags().StringVarP(&clusterConfigPath, "config", "c", "", "path to the configuration file")
	if err := clusterCmd.MarkPersistentFlagRequired("config"); err != nil {
		panic(err)
	}
}

func writeMemberTable(w io.Writer, members []cluster.Member) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tAPI_ADDRESS\tROLE\tLEADER") //nolint:errcheck
	for _, m := range members {
		name := m.Name
		if name == "" {
			name = "-"
		}
		api := m.APIAddress
		if api == "" {
			api = "-"
		}
		leader := ""
		if m.Leader {
			leader = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, m.Address, api, m.Role, leader) //nolint:errcheck
	}
	return tw.Flush()
}
