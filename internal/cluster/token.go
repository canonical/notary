package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// joinTokenBytes is the size of the random material in a join token. 256 bits
// puts the token far beyond brute force, which matters because a valid token is
// on its own sufficient to obtain a cluster certificate.
const joinTokenBytes = 32

// GenerateJoinToken returns a new join token and the hash to store alongside it.
//
// The token itself is shown to the operator once and never persisted; only the
// hash reaches the database, so a database dump cannot be replayed into a join.
func GenerateJoinToken() (token string, hash string, err error) {
	material := make([]byte, joinTokenBytes)
	for {
		if _, err := rand.Read(material); err != nil {
			return "", "", fmt.Errorf("failed to generate join token: %w", err)
		}

		token = base64.RawURLEncoding.EncodeToString(material)

		// A token is pasted straight into `notary cluster join`, where a leading
		// '-' is read as a flag. Re-rolling costs nothing and keeps every token
		// usable, including in commands an operator writes by hand. It is the
		// same concern that makes this the URL-safe alphabet rather than the
		// standard one.
		if !strings.HasPrefix(token, "-") {
			break
		}
	}

	return token, HashJoinToken(token), nil
}

// HashJoinToken returns the stored representation of a join token.
//
// A plain SHA-256 is deliberate rather than a password hash: the token is 256
// bits of uniform random material, so there is no low-entropy guess space for a
// slow hash to defend against.
func HashJoinToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
