package authentication_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestSetUpJWTSecretAssignsMemory(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if len(database.JWTSecret) == 0 {
		t.Fatal("expected JWT secret in memory after first create")
	}
	got, err := database.GetJWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, database.JWTSecret) {
		t.Fatal("in-memory JWT secret does not match database")
	}
}

func TestSetUpJWTSecretReloadsExisting(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	want := append([]byte(nil), database.JWTSecret...)
	database.JWTSecret = nil
	if err := authentication.SetUpJWTSecret(database); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, database.JWTSecret) {
		t.Fatal("reloaded JWT secret does not match original")
	}
}

// A losing insert takes the fast reload path only when it reports
// ErrAlreadyExists; anything else falls back to the slower retry.
func TestCreateJWTSecretTwiceReportsAlreadyExists(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	err := database.CreateJWTSecret([]byte("another-secret-value-32-bytes---"))
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("got %v, want %v", err, db.ErrAlreadyExists)
	}
}

// On a fresh cluster several members can find no secret at once, all generate a
// candidate, and only one insert wins. Every member must end up holding the
// stored secret rather than its own discarded candidate. Run this with -race:
// the contended failure only shows up under that timing.
func TestSetUpJWTSecretConcurrentCreateConverges(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if _, err := database.Conn.PlainDB().Exec("DELETE FROM jwt_secret"); err != nil {
		t.Fatalf("clear jwt_secret: %v", err)
	}

	const members = 4
	// Shallow copies share the connection and prepared statements but each keeps
	// its own JWTSecret field, standing in for separate nodes.
	repos := make([]*db.DatabaseRepository, members)
	for i := range repos {
		clone := *database
		clone.JWTSecret = nil
		repos[i] = &clone
	}

	errs := make([]error, members)
	var wg sync.WaitGroup
	for i := range repos {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = authentication.SetUpJWTSecret(repos[i])
		}(i)
	}
	wg.Wait()

	stored, err := database.GetJWTSecret()
	if err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("no secret was stored")
	}
	for i := range repos {
		if errs[i] != nil {
			t.Fatalf("member %d: %v", i, errs[i])
		}
		if !bytes.Equal(repos[i].JWTSecret, stored) {
			t.Fatalf("member %d holds a secret that differs from the stored one", i)
		}
	}
}
