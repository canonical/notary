package cluster

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
	"github.com/canonical/go-dqlite/v3/client"
)

// These tests require Linux and libdqlite. Disable background role adjustment
// so the two-node regression really starts with a voter and a spare.
func TestRemovalKeepsClusterWritable(t *testing.T) {
	for _, viaCLI := range []bool{false, true} {
		for _, scenario := range []struct {
			name         string
			size, target int
		}{
			{"sole-voter", 2, 0}, {"three-member-leader", 3, 0}, {"non-leader", 3, 2},
		} {
			t.Run(fmt.Sprintf("%s/cli=%t", scenario.name, viaCLI), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				var nodes []*Node
				var dirs []string
				var databases []*sql.DB
				for i := 0; i < scenario.size; i++ {
					dir := t.TempDir()
					addr, err := FreeAddress()
					if err != nil {
						t.Fatal(err)
					}
					opts := []app.Option{app.WithAddress(addr), app.WithRolesAdjustmentFrequency(time.Hour)}
					if i > 0 {
						opts = append(opts, app.WithCluster([]string{nodes[0].Address()}))
					}
					a, err := app.New(dir, opts...)
					if err != nil {
						t.Fatal(err)
					}
					n := &Node{app: a}
					t.Cleanup(func() {
						if n.app != nil {
							_ = n.app.Close()
						}
					})
					if err := a.Ready(ctx); err != nil {
						t.Fatal(err)
					}
					nodes = append(nodes, n)
					dirs = append(dirs, dir)
					db, err := n.Open(ctx)
					if err != nil {
						t.Fatal(err)
					}
					databases = append(databases, db)
					t.Cleanup(func() { _ = db.Close() })
				}
				db := databases[0]
				for _, query := range []string{
					`CREATE TABLE cluster_members (name TEXT PRIMARY KEY, address TEXT, api_address TEXT)`,
					`CREATE TABLE removal_data (id INTEGER PRIMARY KEY, value TEXT)`,
					`INSERT INTO removal_data VALUES (1, 'before')`,
				} {
					if _, err := db.ExecContext(ctx, query); err != nil {
						t.Fatal(err)
					}
				}
				for i, n := range nodes {
					if err := RegisterMember(ctx, db, fmt.Sprintf("node%d", i), n.Address(), ""); err != nil {
						t.Fatal(err)
					}
				}
				cli, err := nodes[0].app.FindLeader(ctx)
				if err != nil {
					t.Fatal(err)
				}
				members, err := cli.Cluster(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range members {
					if m.ID == nodes[0].app.ID() {
						continue
					}
					if scenario.size == 2 {
						if m.Role != client.Spare {
							t.Fatalf("survivor role = %v, want spare", m.Role)
						}
					} else if m.Role != client.Voter {
						if err := cli.Assign(ctx, m.ID, client.Voter); err != nil {
							t.Fatal(err)
						}
					}
				}
				_ = cli.Close()
				target := fmt.Sprintf("node%d", scenario.target)
				// Always receive the request on a surviving node, different from target.
				if viaCLI {
					err = RemoveMemberTLS(ctx, dirs[1], nil, target)
				} else {
					err = RemoveMemberOnNode(ctx, nodes[1], databases[1], target)
				}
				if err != nil {
					t.Fatalf("remove: %v", err)
				}
				// Stop the evicted process: subsequent SQL must be served by survivors.
				if err := nodes[scenario.target].app.Close(); err != nil {
					t.Fatal(err)
				}
				nodes[scenario.target].app = nil
				survivors, err := nodes[1].MembersWithNames(ctx, databases[1])
				if err != nil {
					t.Fatal(err)
				}
				if len(survivors) != scenario.size-1 {
					t.Fatalf("members = %v", survivors)
				}
				for _, m := range survivors {
					if m.Name == target {
						t.Fatalf("target remains: %v", survivors)
					}
				}
				fresh, err := OpenClientDBTLS(ctx, dirs[1], nil)
				if err != nil {
					t.Fatal(err)
				}
				defer fresh.Close() //nolint:errcheck
				var value string
				if err := fresh.QueryRowContext(ctx, `SELECT value FROM removal_data WHERE id=1`).Scan(&value); err != nil || value != "before" {
					t.Fatalf("persisted value=%q err=%v", value, err)
				}
				if _, err := fresh.ExecContext(ctx, `INSERT INTO removal_data VALUES (2, 'after')`); err != nil {
					t.Fatalf("write after eviction: %v", err)
				}
				if err := fresh.QueryRowContext(ctx, `SELECT value FROM removal_data WHERE id=2`).Scan(&value); err != nil || value != "after" {
					t.Fatalf("new value=%q err=%v", value, err)
				}
				if scenario.size == 2 {
					if err := RemoveMemberOnNode(ctx, nodes[1], fresh, "node1"); !errors.Is(err, ErrLastMember) {
						t.Fatalf("final member: %v", err)
					}
				}
			})
		}
	}
}
