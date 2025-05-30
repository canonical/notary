package db

import (
	"context"
	"path/filepath"
	"testing"
)

var PK = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAniOVWy/tCYRbmthnGPRko7kKT6rOtbebZLTzE+u8/5sfurCO
FhmvumyLsFbxtEM6/VAdk1iiOvbx7JOGKR/XGL+U2xIUl0nF3cE7yxy6RxkqaaRA
TD3sF07Atk10dqjAqyE70ivAO6QHj3DvlqYiYcXqNzPSmpLV3/q+jndu0TvmaeWb
93LesBUuHTlPL0aL/8vVykINVoxd53+naq41Dc5rKA7qva+1VI4MyeDkA3+9ueJd
OKYbvw+08TC8uQ9rlaXOebRaNU/j/1EtHLKbmtNVsNv5PzQb0kOWrd/UNz0j7/T6
jc8MVBFMVXqmSDyHZyq5xfkCrwbhDGtQ+3U8kQIDAQABAoIBAADaYJPFSM7cxZp6
n+bp3xQwbecp/NtXYCWGpxrF96nB5Zr7WQndcGXrMC9MDxnYWhRWmxE8g2QEaTUh
WCzRvYEbpp8OUaQoXLKRIwxJ1XH88hOlBDKGa+cLM1rhujQ0vZ99XSIZfwayADcw
g5StRN6rMNPZ8gZyzofqtX363uh5UJYxbDNjb56TTCjHxTZStZaKbnCce7SmbZ9a
1MCPnMQ3KD/itxpIpSmpb8zu6AIPyIsG4T0ctGsP5CcXWkc7gStCH7+Y1MlrgYqj
v6I9ATranUJTu6FNQstPSrJ3TeiB3cWkJKSlh1FOOMsRZG4W/eDghG3JDnll7ZKf
1vFJAIECgYEA2y+zilFHooCkq5ze0eCknSFQFRcU5zSvoWLpoVTy3FJyWZUcVi7W
+aJ2Ok+jF9AmkTETOtioJl/PRa26CEawIWtgE9wjNxc0Qi0RNdvPfcmcL/KDGaok
aL887qiuxPfKISbOwx6R7ip5CaXwPIHj2zS9Ae5MMRfI0PwxOXeMjYECgYEAuLML
oWSI6mEDU3N5tWAwhJ2wSEPVpR98vaP78erNvblJqJKBYYWKN6YiDDtNZOmfIP64
KV2iXMqy49VQgqFjPQAioh8GhH/CzS319ywmE9tgMN/cFH68r3KccY2OUuVGi5kp
JgqYGWjiL/riHIuzvd4cc+5QrfWiC72teA2JVxECgYBtNPYii17Cs4/YRX+rWF8M
PwXUjDyI+fIr2cmH7XhXl+iLg8SrmAjaNjzrzrP28GnW23m2Ty5weDoggG95Iict
b39eRcdx8mjCNAwoJo3aIXJlXVI+nkwnuGjWjEsPrloSbHCGPRv+a0EFMp1guGLb
3An0BVQG/c+7eHvaIxtvgQKBgQCwJWGELEM/dAIeBlUem3vqHhFO+hK5BcyLd+cC
ErLgq+MJt59YiGkHJZP3Il9vTDcM2qB8IuaDpHTzQC8mRhBEzuo4v2oR117LG3gm
oJ439dJJClXz3eLJWH7G9P+1IyAiZpGNzDC+mv6MT7JxEvL6sudj0PZ00XwXwm+7
vP0sYQKBgQCG70DYGJaboUavfywNBVqkh9/6TTvURM6F0cszjSXUfAqWA18VXA3d
m06g0yBoeDCgZUtdd5Y7GtCX2/tcKR7pZK8tO5rDccnpi0qn/1Z0qNXoUuk9VyFs
MUksCY/7cVN4D5j0KDDI1OlYoKWDshk+QqLPPRNnlicXPSJGyziKaA==
-----END RSA PRIVATE KEY-----
`

// TestPrivateKeyEncryption verifies that the private key is properly encrypted in the database
func TestPrivateKeyEncryption(t *testing.T) {
	tempDir := t.TempDir()
	database, err := NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	pkID, err := database.CreatePrivateKey(PK)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}

	pk := PrivateKey{PrivateKeyID: pkID}
	err = database.conn.Query(context.Background(), database.stmts.GetPrivateKey, pk).Get(&pk)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if pk.PrivateKeyPEM == PK {
		t.Fatal("Private key is stored in plaintext!")
	}

	decryptedPK, err := database.GetPrivateKey(ByPrivateKeyID(pkID))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if decryptedPK.PrivateKeyPEM != PK {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			decryptedPK.PrivateKeyPEM, PK)
	}

	decryptedManually, err := Decrypt(pk.PrivateKeyPEM, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != PK {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, PK)
	}
}
