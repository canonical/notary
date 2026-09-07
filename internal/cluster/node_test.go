package cluster_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

func TestStartOpenAndResume(t *testing.T) {
	dir := t.TempDir()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatalf("free address: %v", err)
	}

	node, err := cluster.Start(cluster.Options{Dir: dir, Address: addr})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := node.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("close node: %v", err)
	}

	if !cluster.HasState(dir) {
		t.Fatal("expected dqlite identity after bootstrap")
	}

	resumed, err := cluster.Start(cluster.Options{Dir: dir, Address: addr})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer resumed.Close() //nolint:errcheck
	db2, err := resumed.Open(ctx)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close() //nolint:errcheck
	if _, err := db2.ExecContext(ctx, `INSERT INTO t (id) VALUES (1)`); err != nil {
		t.Fatalf("insert after resume: %v", err)
	}
}

func TestJoinRequiresTLS(t *testing.T) {
	_, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: "127.0.0.1:1",
		Join:    []string{"127.0.0.1:2"},
	})
	if err == nil {
		t.Fatal("expected error when joining without cluster TLS")
	}
}

func TestJoinInvalidTLSWrapsError(t *testing.T) {
	_, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: "127.0.0.1:1",
		Join:    []string{"127.0.0.1:2"},
		TLSCert: []byte("not-a-certificate"),
		TLSKey:  []byte("not-a-key"),
	})
	if err == nil {
		t.Fatal("expected error when joining with invalid cluster TLS")
	}
	if !strings.Contains(err.Error(), "join cluster at 127.0.0.1:2") {
		t.Fatalf("expected join wrap, got %v", err)
	}
	if !strings.Contains(err.Error(), "cluster TLS") {
		t.Fatalf("expected TLS cause, got %v", err)
	}
}

func TestTwoNodesShareData(t *testing.T) {
	certPEM, keyPEM := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}

	dir1 := t.TempDir()
	node1, err := cluster.Start(cluster.Options{
		Dir:     dir1,
		Address: addr1,
		TLSCert: certPEM,
		TLSKey:  keyPEM,
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer node1.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db1, err := node1.Open(ctx)
	if err != nil {
		t.Fatalf("open node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	if _, err := db1.ExecContext(ctx, `CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db1.ExecContext(ctx, `INSERT INTO t (id, n) VALUES (1, 'ok')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	node2, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr2,
		Join:    []string{addr1},
		TLSCert: certPEM,
		TLSKey:  keyPEM,
	})
	if err != nil {
		t.Fatalf("start node2: %v", err)
	}
	defer node2.Close() //nolint:errcheck

	db2, err := node2.Open(ctx)
	if err != nil {
		t.Fatalf("open node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	var n string
	if err := db2.QueryRowContext(ctx, `SELECT n FROM t WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read from joiner: %v", err)
	}
	if n != "ok" {
		t.Fatalf("got %q", n)
	}

	members, err := node2.Members(ctx)
	if err != nil {
		t.Fatalf("members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	var sawLeader bool
	for _, m := range members {
		if m.Leader {
			sawLeader = true
		}
	}
	if !sawLeader {
		t.Fatal("expected a leader")
	}

	queried, err := cluster.QueryMembers(ctx, dir1, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("query members: %v", err)
	}
	if len(queried) != 2 {
		t.Fatalf("query members: got %d, want 2", len(queried))
	}

	if err := node1.Close(); err != nil {
		t.Fatalf("handover close node1: %v", err)
	}
	var n2 string
	if err := db2.QueryRowContext(ctx, `SELECT n FROM t WHERE id = 1`).Scan(&n2); err != nil {
		t.Fatalf("read after leader handover: %v", err)
	}
	if n2 != "ok" {
		t.Fatalf("got %q", n2)
	}
}

func TestIsLeaderSingleNode(t *testing.T) {
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	node, err := cluster.Start(cluster.Options{Dir: t.TempDir(), Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ok, leaderAddr, err := node.IsLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected single node to be leader")
	}
	if leaderAddr != addr {
		t.Fatalf("leader address %q, want %q", leaderAddr, addr)
	}
}

func TestIsLeaderJoinerIsNotLeader(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("add token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	ok1, leader1, err := db1.Node.IsLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ok2, leader2, err := db2.Node.IsLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok1 {
		t.Fatal("expected bootstrap node to be leader")
	}
	if ok2 {
		t.Fatal("expected joiner not to be leader")
	}
	if leader1 != addr1 || leader2 != addr1 {
		t.Fatalf("leader addresses bootstrap=%q joiner=%q want %q", leader1, leader2, addr1)
	}
}

func TestMemberAPIAddressAndLeaderLookup(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("add token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		APIAddress:   "127.0.0.1:8444",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	members, err := db2.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byName := map[string]cluster.Member{}
	for _, m := range members {
		byName[m.Name] = m
	}
	if byName["node1"].APIAddress != "127.0.0.1:8443" {
		t.Fatalf("node1 api_address %q", byName["node1"].APIAddress)
	}
	if byName["node2"].APIAddress != "127.0.0.1:8444" {
		t.Fatalf("node2 api_address %q", byName["node2"].APIAddress)
	}
	if got := cluster.APIAddressFor(ctx, db2.Conn.PlainDB(), addr1); got != "127.0.0.1:8443" {
		t.Fatalf("leader API address %q", got)
	}
	if got := cluster.APIAddressFor(ctx, db2.Conn.PlainDB(), "127.0.0.1:1"); got != "127.0.0.1:1" {
		t.Fatalf("missing member should fall back, got %q", got)
	}
}

func TestThreeNodeVoterPromotionAndFailover(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr3, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	token2, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token node2: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token2,
		APIAddress:   "127.0.0.1:8444",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	token3, err := db1.IssueJoinToken(ctx, "node3")
	if err != nil {
		t.Fatalf("token node3: %v", err)
	}
	db3, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr3,
		Name:         "node3",
		JoinToken:    token3,
		APIAddress:   "127.0.0.1:8445",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node3: %v", err)
	}
	defer db3.Close() //nolint:errcheck

	waitForVoters(t, ctx, db1, 3)

	if err := db2.Close(); err != nil {
		t.Fatalf("close node2: %v", err)
	}
	var writeErr error
	for {
		_, writeErr = db1.IssueJoinToken(ctx, "node4")
		if writeErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("write after losing one voter: %v", writeErr)
		case <-time.After(200 * time.Millisecond):
		}
	}
	members, err := db3.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list from remaining member: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3 (dead member still in raft)", len(members))
	}
}

func stubJoinExchange(t *testing.T, database *db.DatabaseRepository, dqliteAddr string) {
	t.Helper()
	orig := cluster.ExchangeJoinToken
	t.Cleanup(func() { cluster.ExchangeJoinToken = orig })
	cluster.ExchangeJoinToken = func(ctx context.Context, raw string) (cluster.JoinMaterial, error) {
		tok, err := cluster.DecodeJoinToken(raw)
		if err != nil {
			return cluster.JoinMaterial{}, err
		}
		material, err := cluster.RedeemJoinToken(ctx, database.Conn.PlainDB(), tok, database.TLSCert, database.TLSKey)
		if err != nil {
			return cluster.JoinMaterial{}, err
		}
		material.Join = []string{dqliteAddr}
		return material, nil
	}
}

func TestJoinTokenYAMLCertMismatch(t *testing.T) {
	certPEM, keyPEM := mustClusterCert(t)
	httpsCert, _ := mustClusterCert(t)
	otherCert, otherKey := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	dir1 := t.TempDir()
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1,
		Address:      addr1,
		Name:         "node1",
		TLSCert:      certPEM,
		TLSKey:       keyPEM,
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("add token: %v", err)
	}

	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cluster.Start(cluster.Options{
		Dir:       t.TempDir(),
		Address:   addr2,
		Name:      "node2",
		JoinToken: token,
		TLSCert:   otherCert,
		TLSKey:    otherKey,
	})
	if err == nil {
		t.Fatal("expected error when YAML cert does not match joined cluster TLS")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v", err)
	}
}

func TestJoinTokenAndRemove(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	dir1 := t.TempDir()
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1,
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("add token: %v", err)
	}

	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	members, err := db2.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	names := map[string]bool{}
	for _, m := range members {
		names[m.Name] = true
	}
	if !names["node1"] || !names["node2"] {
		t.Fatalf("names = %v", names)
	}

	if err := db1.RemoveClusterMember(ctx, "node2"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	members, err = db1.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("got %d members after remove, want 1", len(members))
	}
	if members[0].Name != "node1" {
		t.Fatalf("remaining member %q", members[0].Name)
	}
}

func TestRedeemJoinTokenOnce(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer database.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := database.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("token must not contain a private key")
	}
	token, err := cluster.DecodeJoinToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	material, err := cluster.RedeemJoinToken(ctx, database.Conn.PlainDB(), token, database.TLSCert, database.TLSKey)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if len(material.TLSKey) == 0 || material.ServerName != "node2" {
		t.Fatalf("%+v", material)
	}
	if _, err := cluster.RedeemJoinToken(ctx, database.Conn.PlainDB(), token, database.TLSCert, database.TLSKey); err == nil {
		t.Fatal("expected second redeem to fail")
	} else if !errors.Is(err, cluster.ErrJoinTokenNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestJoinTokenReuseDoesNotJoin(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	_, err = db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      mustFreeAddress(t),
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected reused token to fail")
	}
	if !errors.Is(err, cluster.ErrJoinTokenNotFound) {
		t.Fatalf("got %v", err)
	}
	members, err := db1.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
}

func TestJoinTokenExpiredDoesNotJoin(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := db1.Conn.PlainDB().ExecContext(ctx, `UPDATE cluster_join_tokens SET expires_at = ? WHERE name = ?`, past, "node2"); err != nil {
		t.Fatal(err)
	}

	_, err = db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      mustFreeAddress(t),
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected expired token to fail")
	}
	if !errors.Is(err, cluster.ErrJoinTokenExpired) {
		t.Fatalf("got %v", err)
	}
	members, err := db1.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("got %d members, want 1", len(members))
	}
}

func TestJoinTokenYAMLCertWithoutKey(t *testing.T) {
	cert, _ := mustClusterCert(t)
	_, err := cluster.Start(cluster.Options{
		Dir:       t.TempDir(),
		Address:   "127.0.0.1:1",
		JoinToken: "x",
		TLSCert:   cert,
	})
	if err == nil {
		t.Fatal("expected error when cluster TLS cert is set without key")
	}
	if !strings.Contains(err.Error(), "must both be set") {
		t.Fatalf("got %v", err)
	}
}

func mustFreeAddress(t *testing.T) string {
	t.Helper()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestThreeNodesShareData(t *testing.T) {
	certPEM, keyPEM := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr3, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}

	node1, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr1,
		TLSCert: certPEM,
		TLSKey:  keyPEM,
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer node1.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db1, err := node1.Open(ctx)
	if err != nil {
		t.Fatalf("open node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	if _, err := db1.ExecContext(ctx, `CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db1.ExecContext(ctx, `INSERT INTO t (id, n) VALUES (1, 'ok')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	node2, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr2,
		Join:    []string{addr1},
		TLSCert: certPEM,
		TLSKey:  keyPEM,
	})
	if err != nil {
		t.Fatalf("start node2: %v", err)
	}
	defer node2.Close() //nolint:errcheck

	node3, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr3,
		Join:    []string{addr1},
		TLSCert: certPEM,
		TLSKey:  keyPEM,
	})
	if err != nil {
		t.Fatalf("start node3: %v", err)
	}
	defer node3.Close() //nolint:errcheck

	db3, err := node3.Open(ctx)
	if err != nil {
		t.Fatalf("open node3: %v", err)
	}
	defer db3.Close() //nolint:errcheck

	var n string
	if err := db3.QueryRowContext(ctx, `SELECT n FROM t WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read from third node: %v", err)
	}
	if n != "ok" {
		t.Fatalf("got %q", n)
	}

	members, err := node3.Members(ctx)
	if err != nil {
		t.Fatalf("members: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
}

func mustClusterCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "notary-cluster"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", "notary-cluster"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestRestoreJoinTokenAfterListWouldFail(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cluster.DecodeJoinToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.RedeemJoinToken(ctx, db1.Conn.PlainDB(), tok, db1.TLSCert, db1.TLSKey); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if err := cluster.RestoreJoinToken(ctx, db1.Conn.PlainDB(), tok); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := cluster.RedeemJoinToken(ctx, db1.Conn.PlainDB(), tok, db1.TLSCert, db1.TLSKey); err != nil {
		t.Fatalf("redeem after restore: %v", err)
	}
}

func TestSpentJoinTokenAfterFailedDqliteJoin(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, "127.0.0.1:1")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected dqlite join to fail")
	}
	if !strings.Contains(err.Error(), cluster.JoinIncompleteMessage) {
		t.Fatalf("expected spent-token message, got %v", err)
	}
	_, err = db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
		Logger:       zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected second join with spent token to fail")
	}
}

func TestLeaderLossMidWrite(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	nodes := startThreeNodeCluster(t, httpsCert)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	waitForVoters(t, ctx, nodes[0], 3)

	leader := waitForCurrentLeader(t, ctx, nodes)
	survivor := nodes[0]
	if survivor == leader {
		survivor = nodes[1]
	}

	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("in-flight write panicked: %v", r)
			}
		}()
		_, err := leader.CreateCertificateRequest(tu.AppleCSR, 0)
		errCh <- err
	}()
	if err := leader.Close(); err != nil {
		t.Logf("close leader: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Log("in-flight write completed on the departing leader")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for in-flight write")
	}

	var writeErr error
	for {
		_, writeErr = survivor.CreateCertificateRequest(tu.BananaCSR, 0)
		if writeErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("write after leader loss: %v", writeErr)
		case <-time.After(200 * time.Millisecond):
		}
	}
	csrs, err := survivor.ListCertificateRequests()
	if err != nil {
		t.Fatalf("list after failover: %v", err)
	}
	if len(csrs) == 0 {
		t.Fatal("expected at least the post-failover CSR")
	}
}

func TestACME409NamesNewLeaderAfterFailover(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	nodes := startThreeNodeCluster(t, httpsCert)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	waitForVoters(t, ctx, nodes[0], 3)

	oldLeader := waitForCurrentLeader(t, ctx, nodes)
	if err := oldLeader.Close(); err != nil {
		t.Logf("close old leader: %v", err)
	}
	var remaining []*db.DatabaseRepository
	for _, n := range nodes {
		if n != oldLeader {
			remaining = append(remaining, n)
		}
	}
	newLeader := waitForCurrentLeader(t, ctx, remaining)
	var follower *db.DatabaseRepository
	for _, n := range remaining {
		if n != newLeader {
			follower = n
			break
		}
	}
	if follower == nil {
		t.Fatal("expected a remaining follower")
	}
	ok, leaderAddr, err := follower.Node.IsLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("follower should not be leader")
	}
	retryAddr, fallback := cluster.LookupAPIAddress(ctx, follower.Conn.PlainDB(), leaderAddr)
	if fallback != "" {
		t.Fatalf("expected stored API address, fallback %q", fallback)
	}
	if retryAddr != newLeader.APIAddress {
		t.Fatalf("409 would name %q, want new leader %q", retryAddr, newLeader.APIAddress)
	}
	if retryAddr == oldLeader.APIAddress {
		t.Fatal("409 still names the old leader")
	}
}

func waitForVoters(t *testing.T, ctx context.Context, database *db.DatabaseRepository, want int) {
	t.Helper()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		members, err := database.ListClusterMembers(ctx)
		if err == nil {
			voters := 0
			for _, m := range members {
				if m.Role == "voter" {
					voters++
				}
			}
			if voters >= want {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %d voters: %v", want, err)
		case <-ticker.C:
		}
	}
}

func startThreeNodeCluster(t *testing.T, httpsCert []byte) []*db.DatabaseRepository {
	t.Helper()
	addrs := make([]string, 3)
	for i := range addrs {
		addr, err := cluster.FreeAddress()
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = addr
	}
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addrs[0],
		Name:         "node1",
		HTTPSCert:    httpsCert,
		APIAddress:   "127.0.0.1:8443",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	t.Cleanup(func() { _ = db1.Close() })
	stubJoinExchange(t, db1, addrs[0])

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token2, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatal(err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addrs[1],
		Name:         "node2",
		JoinToken:    token2,
		APIAddress:   "127.0.0.1:8444",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	token3, err := db1.IssueJoinToken(ctx, "node3")
	if err != nil {
		t.Fatal(err)
	}
	db3, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addrs[2],
		Name:         "node3",
		JoinToken:    token3,
		APIAddress:   "127.0.0.1:8445",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node3: %v", err)
	}
	t.Cleanup(func() { _ = db3.Close() })
	return []*db.DatabaseRepository{db1, db2, db3}
}

func waitForCurrentLeader(t *testing.T, ctx context.Context, nodes []*db.DatabaseRepository) *db.DatabaseRepository {
	t.Helper()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, n := range nodes {
			if n == nil || n.Node == nil {
				continue
			}
			ok, _, err := n.Node.IsLeader(ctx)
			if err == nil && ok {
				return n
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for a leader")
		case <-ticker.C:
		}
	}
}
