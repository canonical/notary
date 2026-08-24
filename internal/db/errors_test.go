package db_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

// The entity helpers wrap two errors: the sentinel callers match on, and the
// driver's own error. Losing the second one leaves an operator with nothing but
// "internal error" to go on.
func TestEntityHelpersKeepBothTheSentinelAndTheCause(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	// Closing the connection is the simplest way to make every query fail for a
	// reason the driver can name.
	if err := database.Conn.PlainDB().Close(); err != nil {
		t.Fatalf("Couldn't close the connection: %s", err)
	}

	tests := []struct {
		name string
		run  func() error
	}{
		{"list", func() error { _, err := database.ListClusterMembers(); return err }},
		{"get", func() error { _, err := database.GetClusterMember("1"); return err }},
		{"create", func() error {
			_, err := database.CreateClusterMember("1", "node-1", "10.0.0.1:9000", time.Now().UTC())
			return err
		}},
		{"update", func() error { return database.RecordClusterMemberHeartbeat("1", false, time.Now().UTC()) }},
		{"delete", func() error { return database.DeleteClusterMember("1") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("a query against a closed connection succeeded")
			}
			if !errors.Is(err, db.ErrInternal) {
				t.Errorf("got %v, want it to match ErrInternal", err)
			}
			if !strings.Contains(err.Error(), "closed") {
				t.Errorf("the driver's cause was discarded: %v", err)
			}
		})
	}
}
