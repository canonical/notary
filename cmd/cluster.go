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
	Long: `List cluster members (name, address, role, leader).

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

On the new machine, copy the cluster TLS files, set cluster.name and cluster.address,
then start with the token:

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
		token, err := cluster.IssueJoinToken(ctx, appConfig.DBPath, appConfig.ClusterTLSCertificate, appConfig.ClusterTLSPrivateKey, args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Member %s join token:\n%s\n", args[0], token)
		return nil
	},
}

var clusterRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a cluster member",
	Long: `Remove a named member from the cluster, like lxc cluster remove.

The daemon must be running. This evicts the node from dqlite; stop that
machine's Notary process afterwards.`,
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
		fmt.Fprintf(cmd.OutOrStdout(), "Member %s removed\n", args[0])
		return nil
	},
}

func parseClusterConfig() (*config.AppConfig, error) {
	appConfig, err := config.ParseConfig(clusterCmd.PersistentFlags(), clusterConfigPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse config: %w", err)
	}
	return appConfig, nil
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(clusterListCmd)
	clusterCmd.AddCommand(clusterAddCmd)
	clusterCmd.AddCommand(clusterRemoveCmd)
	clusterCmd.PersistentFlags().StringVarP(&clusterConfigPath, "config", "c", "", "path to the configuration file")
	if err := clusterCmd.MarkPersistentFlagRequired("config"); err != nil {
		panic(err)
	}
}

func writeMemberTable(w io.Writer, members []cluster.Member) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tROLE\tLEADER")
	for _, m := range members {
		name := m.Name
		if name == "" {
			name = "-"
		}
		leader := ""
		if m.Leader {
			leader = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, m.Address, m.Role, leader)
	}
	return tw.Flush()
}
