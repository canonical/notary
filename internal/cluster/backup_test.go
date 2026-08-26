package cluster_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

func dump() []cluster.DumpFile {
	return []cluster.DumpFile{
		{Name: "notary", Data: []byte("main database contents")},
		{Name: "notary-wal", Data: []byte("write ahead log contents")},
	}
}

// writeTarGz builds an archive holding exactly the given entries, so a test can
// hand ExtractDump something WriteDumpArchive would never produce.
func writeTarGz(t *testing.T, path string, entries map[string]string) {
	t.Helper()

	var buffer bytes.Buffer
	gzWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzWriter)
	for name, contents := range entries {
		header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tarWriter.Write([]byte(contents)); err != nil {
			t.Fatalf("failed to write tar contents: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("failed to finish tar: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("failed to finish gzip: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write archive: %v", err)
	}
}

func TestDumpArchiveRoundTrip(t *testing.T) {
	archivePath, err := cluster.WriteDumpArchive(t.TempDir(), dump())
	if err != nil {
		t.Fatalf("failed to write archive: %v", err)
	}

	restored, err := cluster.ExtractDump(archivePath)
	if err != nil {
		t.Fatalf("failed to extract archive: %v", err)
	}

	if len(restored) != len(dump()) {
		t.Fatalf("expected %d files, got %d", len(dump()), len(restored))
	}
	for i, file := range restored {
		if file.Name != dump()[i].Name {
			t.Errorf("expected file %q, got %q", dump()[i].Name, file.Name)
		}
		if !bytes.Equal(file.Data, dump()[i].Data) {
			t.Errorf("contents of %q did not survive the round trip", file.Name)
		}
	}
}

func TestWriteDumpArchiveRejectsAnEmptyDump(t *testing.T) {
	if _, err := cluster.WriteDumpArchive(t.TempDir(), nil); err == nil {
		t.Fatal("expected an empty dump to be rejected")
	}
}

func TestExtractDumpRejectsForeignEntries(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", "/etc/passwd", "notary/../evil", "unrelated"} {
		t.Run(name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			writeTarGz(t, archivePath, map[string]string{name: "payload"})

			if _, err := cluster.ExtractDump(archivePath); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestExtractDumpRejectsAnArchiveWithNoDatabase(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	writeTarGz(t, archivePath, nil)

	if _, err := cluster.ExtractDump(archivePath); err == nil {
		t.Fatal("expected an archive with no database files to be rejected")
	}
}

func TestStageDumpWritesTheWALBesideTheDatabase(t *testing.T) {
	dir := t.TempDir()

	mainPath, err := cluster.StageDump(dir, dump())
	if err != nil {
		t.Fatalf("failed to stage dump: %v", err)
	}

	if mainPath != filepath.Join(dir, "notary") {
		t.Errorf("expected the main database at %q, got %q", filepath.Join(dir, "notary"), mainPath)
	}
	// SQLite finds a WAL by name, so the staged pair only replays if the WAL
	// sits next to the database under exactly this name.
	if _, err := os.Stat(filepath.Join(dir, "notary-wal")); err != nil {
		t.Errorf("expected the WAL to be staged beside the database: %v", err)
	}
}

func TestStageDumpRejectsADumpWithNoDatabase(t *testing.T) {
	files := []cluster.DumpFile{{Name: "notary-wal", Data: []byte("write ahead log contents")}}

	if _, err := cluster.StageDump(t.TempDir(), files); err == nil {
		t.Fatal("expected a dump without its main database file to be rejected")
	}
}

func TestHasState(t *testing.T) {
	t.Run("a node that has never started has no state", func(t *testing.T) {
		if occupied, err := cluster.HasState(t.TempDir()); err != nil || occupied {
			t.Fatalf("expected no state, got %v (err %v)", occupied, err)
		}
	})

	t.Run("a node that has started has state", func(t *testing.T) {
		stateDir := t.TempDir()
		dataDir := cluster.DataDir(stateDir)
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatalf("failed to create data directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "info.yaml"), []byte("ID: 1\n"), 0o600); err != nil {
			t.Fatalf("failed to write node info: %v", err)
		}

		if occupied, err := cluster.HasState(stateDir); err != nil || !occupied {
			t.Fatalf("expected state to be found, got %v (err %v)", occupied, err)
		}
	})
}
