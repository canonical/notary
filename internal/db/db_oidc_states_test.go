package db_test

import (
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

func TestOIDCStateStoreAndValidate(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if err := database.StoreOIDCState("s1", "Mozilla/5.0"); err != nil {
		t.Fatal(err)
	}
	if !database.ValidateOIDCState("s1", "Mozilla/5.0") {
		t.Fatal("expected valid state")
	}
	if database.ValidateOIDCState("s1", "Mozilla/5.0") {
		t.Fatal("state must be one-time")
	}
}

func TestOIDCStateWrongUserAgentConsumes(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if err := database.StoreOIDCState("s1", "Chrome"); err != nil {
		t.Fatal(err)
	}
	if database.ValidateOIDCState("s1", "Firefox") {
		t.Fatal("wrong user agent must fail")
	}
	if database.ValidateOIDCState("s1", "Chrome") {
		t.Fatal("state should be consumed after failed validation")
	}
}

func TestOIDCStateSharedAcrossClones(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	clone := *database
	if err := database.StoreOIDCState("shared", "Agent"); err != nil {
		t.Fatal(err)
	}
	if !clone.ValidateOIDCState("shared", "Agent") {
		t.Fatal("callback on another member must see the stored state")
	}
}

func TestOIDCStateCleanup(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if err := database.StoreOIDCState("fresh", "Agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Conn.PlainDB().Exec(`UPDATE oidc_states SET created_at = '2000-01-01T00:00:00Z' WHERE state = 'fresh'`); err != nil {
		t.Fatal(err)
	}
	if err := database.StoreOIDCState("keep", "Agent"); err != nil {
		t.Fatal(err)
	}
	if err := database.CleanupOIDCStates(); err != nil {
		t.Fatal(err)
	}
	if database.CountOIDCStates() != 1 {
		t.Fatalf("got %d states after cleanup", database.CountOIDCStates())
	}
}

func TestOIDCStateConcurrentConsumeOnce(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if err := database.StoreOIDCState("s1", "Mozilla/5.0"); err != nil {
		t.Fatal(err)
	}
	const n = 8
	results := make(chan bool, n)
	for range n {
		go func() {
			results <- database.ValidateOIDCState("s1", "Mozilla/5.0")
		}()
	}
	var ok int
	for range n {
		if <-results {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("got %d successful consumes, want 1", ok)
	}
}
