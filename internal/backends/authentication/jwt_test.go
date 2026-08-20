package authentication_test

import (
	"bytes"
	"testing"

	"github.com/canonical/notary/internal/backends/authentication"
	tu "github.com/canonical/notary/internal/testutils"
)

// A node that generates the JWT secret must also load it, otherwise it signs
// sessions with an empty key and no other cluster member accepts them.
func TestSetUpJWTSecretLoadsANewlyGeneratedSecret(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if _, err := database.Conn.PlainDB().Exec("DELETE FROM jwt_secret"); err != nil {
		t.Fatalf("Couldn't clear the JWT secret: %s", err)
	}
	database.JWTSecret = nil

	if err := authentication.SetUpJWTSecret(database); err != nil {
		t.Fatalf("Couldn't set up the JWT secret: %s", err)
	}

	if len(database.JWTSecret) == 0 {
		t.Fatal("JWT secret was generated but not loaded into the repository")
	}
	stored, err := database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't read the stored JWT secret: %s", err)
	}
	if !bytes.Equal(database.JWTSecret, stored) {
		t.Fatal("the loaded JWT secret does not match the stored one")
	}
}
