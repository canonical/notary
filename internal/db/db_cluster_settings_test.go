package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestACMEIssuerRoundTrip(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.SetACMEIssuerNodeID("7"); err != nil {
		t.Fatalf("couldn't set ACME issuer: %s", err)
	}
	got, err := database.GetACMEIssuerNodeID()
	if err != nil {
		t.Fatalf("couldn't get ACME issuer: %s", err)
	}
	if got != "7" {
		t.Errorf("got issuer %q, want 7", got)
	}

	if err := database.SetACMEIssuerNodeID("3"); err != nil {
		t.Fatalf("couldn't replace ACME issuer: %s", err)
	}
	got, err = database.GetACMEIssuerNodeID()
	if err != nil {
		t.Fatalf("couldn't get replaced ACME issuer: %s", err)
	}
	if got != "3" {
		t.Errorf("got issuer %q, want 3", got)
	}
}

func TestGetACMEIssuerWhenUnset(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if _, err := database.GetACMEIssuerNodeID(); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetACMEIssuerRejectsEmptyNodeID(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.SetACMEIssuerNodeID(""); !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestClearACMEIssuerIsIdempotent(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.ClearACMEIssuer(); err != nil {
		t.Fatalf("clearing an absent issuer failed: %s", err)
	}
	if err := database.SetACMEIssuerNodeID("1"); err != nil {
		t.Fatalf("couldn't set ACME issuer: %s", err)
	}
	if err := database.ClearACMEIssuer(); err != nil {
		t.Fatalf("couldn't clear ACME issuer: %s", err)
	}
	if _, err := database.GetACMEIssuerNodeID(); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after clear, got %v", err)
	}
	if err := database.ClearACMEIssuer(); err != nil {
		t.Fatalf("clearing twice failed: %s", err)
	}
}
