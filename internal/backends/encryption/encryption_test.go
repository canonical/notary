package encryption_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

func TestSetUpEncryptionKeyReloadsExisting(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	want := append([]byte(nil), database.EncryptionKey...)
	database.EncryptionKey = nil
	if err := encryption.SetUpEncryptionKey(database, encryption.NoEncryptionBackend{}, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, database.EncryptionKey) {
		t.Fatal("reloaded encryption key does not match original")
	}
}

func TestSetUpEncryptionKeyConcurrentCreateConverges(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	if _, err := database.Conn.PlainDB().Exec("DELETE FROM encryption_keys"); err != nil {
		t.Fatalf("clear encryption_keys: %v", err)
	}

	const members = 4
	repos := make([]*db.DatabaseRepository, members)
	for i := range repos {
		clone := *database
		clone.EncryptionKey = nil
		repos[i] = &clone
	}

	errs := make([]error, members)
	var wg sync.WaitGroup
	for i := range repos {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = encryption.SetUpEncryptionKey(repos[i], encryption.NoEncryptionBackend{}, zap.NewNop())
		}(i)
	}
	wg.Wait()

	stored, err := database.GetEncryptionKey()
	if err != nil {
		t.Fatalf("read stored key: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("no encryption key was stored")
	}
	for i := range repos {
		if errs[i] != nil {
			t.Fatalf("member %d: %v", i, errs[i])
		}
		if !bytes.Equal(repos[i].EncryptionKey, stored) {
			t.Fatalf("member %d holds a key that differs from the stored one", i)
		}
	}
}
