package db_test

import (
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestClusterMemberHeartbeatRoundTrip(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterMember("1", "node-1", "10.0.0.1:9000", now); err != nil {
		t.Fatalf("Couldn't create a cluster member: %s", err)
	}

	member, err := database.GetClusterMember("1")
	if err != nil {
		t.Fatalf("Couldn't read the cluster member: %s", err)
	}
	if member.Heartbeat != nil {
		t.Errorf("a member that never beat has heartbeat %v, want nil", *member.Heartbeat)
	}
	if member.Online(now) {
		t.Error("a member that never beat reads as online")
	}

	if err := database.RecordClusterMemberHeartbeat("1", true, now); err != nil {
		t.Fatalf("Couldn't record a heartbeat: %s", err)
	}

	member, err = database.GetClusterMember("1")
	if err != nil {
		t.Fatalf("Couldn't read the cluster member: %s", err)
	}
	if member.Heartbeat == nil || *member.Heartbeat != now.Unix() {
		t.Errorf("got heartbeat %v, want %d", member.Heartbeat, now.Unix())
	}
	if !member.Sealed {
		t.Error("the recorded seal state was not kept")
	}
	if !member.Online(now) {
		t.Error("a member that just beat reads as offline")
	}
}

// A heartbeat only counts for as long as the offline threshold, which is what
// turns a stopped node into an OFFLINE member without anyone polling it.
func TestClusterMemberGoesOfflineAfterTheThreshold(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	// Heartbeats are stored as whole Unix seconds, so a sub-second `now` would
	// put the boundary case fractionally past the threshold.
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := database.CreateClusterMember("1", "node-1", "10.0.0.1:9000", now); err != nil {
		t.Fatalf("Couldn't create a cluster member: %s", err)
	}
	if err := database.RecordClusterMemberHeartbeat("1", false, now); err != nil {
		t.Fatalf("Couldn't record a heartbeat: %s", err)
	}

	member, err := database.GetClusterMember("1")
	if err != nil {
		t.Fatalf("Couldn't read the cluster member: %s", err)
	}

	if !member.Online(now.Add(db.OfflineThreshold)) {
		t.Error("a member exactly at the threshold reads as offline")
	}
	if member.Online(now.Add(db.OfflineThreshold + time.Second)) {
		t.Error("a member past the threshold still reads as online")
	}
}

func TestRecordClusterMemberHeartbeatRejectsAnEmptyNodeID(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.RecordClusterMemberHeartbeat("", false, time.Now().UTC()); err == nil {
		t.Fatal("an empty node ID was accepted")
	}
}
