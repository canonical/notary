package db_test

import (
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestJWTSecretEncryption(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	jwtSecret := db.JWTSecret{ID: 1}
	row := database.Conn.PlainDB().QueryRow("SELECT * FROM jwt_secret WHERE id = ?", jwtSecret.ID)
	err := row.Scan(&jwtSecret.ID, &jwtSecret.EncryptedSecret)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}
	if jwtSecret.EncryptedSecret == "" {
		t.Fatal("JWT secret is empty")
	}
}
