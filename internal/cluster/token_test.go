package cluster_test

import (
	"strings"
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

// A token is pasted straight into `notary cluster join`, which reads a leading
// '-' as a flag. Roughly one base64url string in 64 starts with one, so this
// would otherwise fail for a small share of tokens and look like a bad token.
func TestGenerateJoinTokenNeverStartsWithADash(t *testing.T) {
	for range 2000 {
		token, hash, err := cluster.GenerateJoinToken()
		if err != nil {
			t.Fatalf("couldn't generate a join token: %s", err)
		}
		if strings.HasPrefix(token, "-") {
			t.Fatalf("token %q starts with a dash", token)
		}
		if hash != cluster.HashJoinToken(token) {
			t.Fatal("the returned hash is not the hash of the returned token")
		}
	}
}
