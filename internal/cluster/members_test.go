package cluster

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/canonical/go-dqlite/v3/client"
	_ "github.com/mattn/go-sqlite3"
)

type removalCluster struct {
	nodes           []client.NodeInfo
	leader          uint64
	calls           []string
	fail            string
	lostResponse    bool
	unchangedLeader bool
}
type removalClient struct {
	cluster *removalCluster
	leader  uint64
}

func (c *removalClient) Close() error { return nil }
func (c *removalClient) Cluster(context.Context) ([]client.NodeInfo, error) {
	return append([]client.NodeInfo(nil), c.cluster.nodes...), nil
}
func (c *removalClient) Leader(context.Context) (*client.NodeInfo, error) {
	for _, n := range c.cluster.nodes {
		if n.ID == c.cluster.leader {
			return &n, nil
		}
	}
	return nil, nil
}
func (c *removalClient) action(action string, id uint64) error {
	c.cluster.calls = append(c.cluster.calls, fmt.Sprintf("%s:%d", action, id))
	if c.cluster.fail == action {
		return errors.New("injected " + action)
	}
	if c.leader != c.cluster.leader {
		return errors.New("stale leader connection")
	}
	return nil
}
func (c *removalClient) Assign(_ context.Context, id uint64, role client.NodeRole) error {
	if err := c.action("assign", id); err != nil {
		return err
	}
	for i := range c.cluster.nodes {
		if c.cluster.nodes[i].ID == id {
			c.cluster.nodes[i].Role = role
		}
	}
	return nil
}
func (c *removalClient) Transfer(_ context.Context, id uint64) error {
	if err := c.action("transfer", id); err != nil {
		return err
	}
	if !c.cluster.unchangedLeader {
		c.cluster.leader = id
	}
	return nil
}
func (c *removalClient) Remove(_ context.Context, id uint64) error {
	if err := c.action("remove", id); err != nil {
		return err
	}
	for i, n := range c.cluster.nodes {
		if n.ID == id {
			c.cluster.nodes = append(c.cluster.nodes[:i], c.cluster.nodes[i+1:]...)
			break
		}
	}
	if c.cluster.lostResponse {
		return errors.New("lost response")
	}
	return nil
}
func (c *removalCluster) connect(context.Context) (membershipClient, error) {
	c.calls = append(c.calls, "connect")
	if c.fail == "reconnect" && len(c.calls) > 1 {
		return nil, errors.New("injected reconnect")
	}
	return &removalClient{cluster: c, leader: c.leader}, nil
}
func removalDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE cluster_members (name TEXT, address TEXT, api_address TEXT);
 INSERT INTO cluster_members VALUES ('one', 'one:9000', ''), ('two', 'two:9000', ''), ('three', 'three:9000', '')`); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestRemoveByName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roles     []client.NodeRole
		target    string
		fail      string
		unchanged bool
		want      []string
		wantErr   bool
	}{
		{name: "sole voter with spare", roles: []client.NodeRole{client.Voter, client.Spare}, target: "one", want: []string{"connect", "assign:2", "transfer:2", "connect", "remove:1"}},
		{name: "standby preferred", roles: []client.NodeRole{client.Voter, client.Spare, client.StandBy}, target: "one", want: []string{"connect", "assign:3", "transfer:3", "connect", "remove:1"}},
		{name: "three voters", roles: []client.NodeRole{client.Voter, client.Voter, client.Voter}, target: "one", want: []string{"connect", "transfer:2", "connect", "remove:1"}},
		{name: "nonleader", roles: []client.NodeRole{client.Voter, client.Voter, client.Voter}, target: "two", want: []string{"connect", "remove:2"}},
		{name: "address", roles: []client.NodeRole{client.Voter, client.Spare}, target: "two:9000", want: []string{"connect", "remove:2"}},
		{name: "promotion failure", roles: []client.NodeRole{client.Voter, client.Spare}, target: "one", fail: "assign", wantErr: true, want: []string{"connect", "assign:2"}},
		{name: "transfer failure", roles: []client.NodeRole{client.Voter, client.Spare}, target: "one", fail: "transfer", wantErr: true, want: []string{"connect", "assign:2", "transfer:2"}},
		{name: "reconnect failure", roles: []client.NodeRole{client.Voter, client.Voter}, target: "one", fail: "reconnect", wantErr: true, want: []string{"connect", "transfer:2", "connect"}},
		{name: "transfer unconfirmed", roles: []client.NodeRole{client.Voter, client.Voter}, target: "one", unchanged: true, wantErr: true, want: []string{"connect", "transfer:2", "connect"}},
		{name: "final member", roles: []client.NodeRole{client.Voter}, target: "one", wantErr: true, want: []string{"connect"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := removalDB(t)
			c := &removalCluster{leader: 1, fail: tc.fail, unchangedLeader: tc.unchanged}
			for i, role := range tc.roles {
				c.nodes = append(c.nodes, client.NodeInfo{ID: uint64(i + 1), Address: []string{"one:9000", "two:9000", "three:9000"}[i], Role: role})
			}
			err := removeByName(context.Background(), c.connect, db, tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tc.name == "final member" && !errors.Is(err, ErrLastMember) {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(c.calls, tc.want) {
				t.Fatalf("calls = %v, want %v", c.calls, tc.want)
			}
			if tc.wantErr && len(c.nodes) != len(tc.roles) {
				t.Fatal("evicted after failure")
			}
		})
	}
}
func TestRemoveByNameRetry(t *testing.T) {
	for _, failure := range []string{"response", "metadata"} {
		for _, target := range []string{"one", "one:9000"} {
			t.Run(failure+target, func(t *testing.T) {
				db := removalDB(t)
				c := &removalCluster{leader: 1, lostResponse: failure == "response", nodes: []client.NodeInfo{{ID: 1, Address: "one:9000", Role: client.Voter}, {ID: 2, Address: "two:9000", Role: client.Spare}}}
				if failure == "metadata" {
					if _, err := db.Exec(`CREATE TRIGGER fail_delete BEFORE DELETE ON cluster_members BEGIN SELECT RAISE(FAIL, 'cleanup failed'); END`); err != nil {
						t.Fatal(err)
					}
				}
				if err := removeByName(context.Background(), c.connect, db, target); err == nil {
					t.Fatal("expected injected failure")
				}
				if len(c.nodes) != 1 {
					t.Fatal("eviction did not commit")
				}
				if failure == "metadata" {
					if _, err := db.Exec(`DROP TRIGGER fail_delete`); err != nil {
						t.Fatal(err)
					}
				}
				c.calls = nil
				if err := removeByName(context.Background(), c.connect, db, target); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(c.calls, []string{"connect"}) {
					t.Fatalf("retry mutated raft: %v", c.calls)
				}
				var count int
				if err := db.QueryRow(`SELECT COUNT(*) FROM cluster_members WHERE name='one'`).Scan(&count); err != nil || count != 0 {
					t.Fatalf("metadata count=%d err=%v", count, err)
				}
				if err := removeByName(context.Background(), c.connect, db, "two"); !errors.Is(err, ErrLastMember) {
					t.Fatalf("last member: %v", err)
				}
			})
		}
	}
}

// A promotion or transfer may commit before a subsequent step fails. Retrying
// must use the current roles and leader instead of repeating the old handover.
func TestRemoveByNameRetryHandover(t *testing.T) {
	for _, failure := range []string{"transfer", "reconnect"} {
		t.Run(failure, func(t *testing.T) {
			db := removalDB(t)
			c := &removalCluster{leader: 1, fail: failure, nodes: []client.NodeInfo{
				{ID: 1, Address: "one:9000", Role: client.Voter},
				{ID: 2, Address: "two:9000", Role: client.Spare},
			}}
			if err := removeByName(context.Background(), c.connect, db, "one"); err == nil {
				t.Fatal("expected failure")
			}
			c.fail = ""
			c.calls = nil
			if err := removeByName(context.Background(), c.connect, db, "one"); err != nil {
				t.Fatal(err)
			}
			want := []string{"connect", "remove:1"}
			if failure == "transfer" {
				want = []string{"connect", "transfer:2", "connect", "remove:1"}
			}
			if !reflect.DeepEqual(c.calls, want) {
				t.Fatalf("calls = %v, want %v", c.calls, want)
			}
		})
	}
}
