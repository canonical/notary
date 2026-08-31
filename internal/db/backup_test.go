package db_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "info.yaml"), []byte("id: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dataDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "nested", "openfga.sqlite"), []byte("sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}

	backupDir := t.TempDir()
	archive, err := db.CreateBackup(dataDir, backupDir)
	if err != nil {
		t.Fatalf("CreateBackup: %s", err)
	}

	restored := filepath.Join(t.TempDir(), "restored")
	if err := db.RestoreBackup(restored, archive); err != nil {
		t.Fatalf("RestoreBackup: %s", err)
	}

	got, err := os.ReadFile(filepath.Join(restored, "info.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "id: 1\n" {
		t.Fatalf("info.yaml: got %q", got)
	}
	got, err = os.ReadFile(filepath.Join(restored, "nested", "openfga.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "sidecar" {
		t.Fatalf("openfga.sqlite: got %q", got)
	}
}

func TestBackupRestoreDqliteData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	srcDir := t.TempDir()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: srcDir,
		Address:      addr,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("NewDatabase: %s", err)
	}
	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, "user@example.com")
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %s", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}

	archive, err := db.CreateBackup(srcDir, t.TempDir())
	if err != nil {
		t.Fatalf("CreateBackup: %s", err)
	}

	dstDir := filepath.Join(t.TempDir(), "dst")
	if err := db.RestoreBackup(dstDir, archive); err != nil {
		t.Fatalf("RestoreBackup: %s", err)
	}

	restored, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dstDir,
		Address:      addr,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("NewDatabase restored: %s", err)
	}
	defer restored.Close() //nolint:errcheck

	got, err := restored.GetCertificateRequest(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("GetCertificateRequest: %s", err)
	}
	if got.UserEmail != "user@example.com" {
		t.Fatalf("user email: got %q", got.UserEmail)
	}
}
