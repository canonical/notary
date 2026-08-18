package cluster

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/canonical/go-dqlite/v3/client"
)

// storeFileName is the file go-dqlite's app package keeps the known cluster
// addresses in, inside the node's data directory. Reading it is how a
// short-lived command finds the cluster without starting a node of its own.
const storeFileName = "cluster.yaml"

// DumpFile is one file of a dqlite database dump: the main database file, or
// its write-ahead log.
type DumpFile struct {
	Name string
	Data []byte
}

// DumpLeader asks the current cluster leader for a copy of Notary's database.
//
// This is dqlite's own network backup primitive, so it needs neither a running
// local node nor access to any node's files: it dials the leader as a client,
// using this node's cluster-internal identity, and gets back the main database
// file and its WAL.
func DumpLeader(ctx context.Context, stateDir string) ([]DumpFile, error) {
	pki, err := LoadPKI(stateDir)
	if err != nil {
		return nil, err
	}

	store, err := client.NewYamlNodeStore(filepath.Join(DataDir(stateDir), storeFileName))
	if err != nil {
		return nil, fmt.Errorf("failed to read the cluster member list: %w", err)
	}

	dial := client.DialFuncWithTLS(client.DefaultDialFunc, dialTLSConfig(pki))

	leader, err := client.FindLeader(ctx, store, client.WithDialFunc(dial))
	if err != nil {
		return nil, fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer leader.Close() //nolint:errcheck

	files, err := leader.Dump(ctx, DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to dump the clustered database: %w", err)
	}
	if len(files) == 0 {
		return nil, errors.New("the cluster leader returned an empty database dump")
	}

	dump := make([]DumpFile, 0, len(files))
	for _, file := range files {
		dump = append(dump, DumpFile{Name: file.Name, Data: file.Data})
	}

	return dump, nil
}

// dialTLSConfig builds the client side of the cluster's mutual TLS.
//
// ServerName is the cluster-internal name every node certificate carries rather
// than the address being dialled: members are verified by their membership of
// the cluster CA, not by hostname, and the address a member advertises is not
// necessarily a name its certificate could ever match.
func dialTLSConfig(pki *PKI) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            pki.Pool,
		Certificates:       []tls.Certificate{pki.Certificate},
		ServerName:         clusterSANDNS,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
}

// WriteDumpArchive packages a database dump into backupDir and returns the path
// of the archive it wrote.
//
// The archive is the same tar.gz the single-file backup path produces, so
// operators and tooling see one backup artifact format regardless of whether the
// deployment is clustered. It just holds two files instead of one.
func WriteDumpArchive(backupDir string, files []DumpFile) (string, error) {
	if len(files) == 0 {
		return "", errors.New("cannot archive an empty database dump")
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	archivePath := filepath.Join(backupDir, fmt.Sprintf("backup_%s.tar.gz", timestamp))

	archiveFile, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to create archive: %w", err)
	}
	defer archiveFile.Close() //nolint:errcheck

	gzWriter := gzip.NewWriter(archiveFile)
	tarWriter := tar.NewWriter(gzWriter)

	modTime := time.Now().UTC()
	for _, file := range files {
		header := &tar.Header{
			Name:    file.Name,
			Mode:    0o600,
			Size:    int64(len(file.Data)),
			ModTime: modTime,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return "", fmt.Errorf("failed to write tar header: %w", err)
		}
		if _, err := tarWriter.Write(file.Data); err != nil {
			return "", fmt.Errorf("failed to write tar contents: %w", err)
		}
	}

	// Both writers buffer, so a failure to close is a failure to write the
	// archive, not a cleanup detail that can be logged and forgotten.
	if err := tarWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to finish the archive: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to compress the archive: %w", err)
	}
	if err := archiveFile.Close(); err != nil {
		return "", fmt.Errorf("failed to write the archive: %w", err)
	}

	return archivePath, nil
}

// ExtractDump reads a database dump back out of an archive written by
// WriteDumpArchive.
func ExtractDump(archivePath string) ([]DumpFile, error) {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close() //nolint:errcheck

	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress archive: %w", err)
	}
	defer gzReader.Close() //nolint:errcheck

	tarReader := tar.NewReader(gzReader)
	var files []DumpFile
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive contents: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if err := validateDumpFileName(header.Name); err != nil {
			return nil, err
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q from the archive: %w", header.Name, err)
		}
		files = append(files, DumpFile{Name: header.Name, Data: data})
	}

	if len(files) == 0 {
		return nil, errors.New("the archive holds no database files")
	}

	return files, nil
}

// validateDumpFileName rejects anything that is not one of the two files a
// dqlite dump of Notary's database consists of.
//
// The archive is operator-supplied, and its entry names are used to build file
// paths, so a name is only ever accepted if it matches exactly what a dump of
// this database is expected to contain. That leaves no room for a traversal or
// for an unrelated file being planted alongside the restored database.
func validateDumpFileName(name string) error {
	if name == DatabaseName || name == DatabaseName+"-wal" {
		return nil
	}

	return fmt.Errorf("the archive holds %q, which is not part of a %q database dump", name, DatabaseName)
}

// StageDump writes a database dump into dir and returns the path of the main
// database file.
//
// The WAL lands next to it under the name SQLite expects, so opening the
// returned path with any SQLite driver replays the WAL and yields the database
// exactly as the leader held it at the moment of the dump.
func StageDump(dir string, files []DumpFile) (string, error) {
	var mainPath string
	for _, file := range files {
		if err := validateDumpFileName(file.Name); err != nil {
			return "", err
		}

		path := filepath.Join(dir, file.Name)
		if err := os.WriteFile(path, file.Data, 0o600); err != nil {
			return "", fmt.Errorf("failed to write %q: %w", file.Name, err)
		}
		if file.Name == DatabaseName {
			mainPath = path
		}
	}

	if mainPath == "" {
		return "", fmt.Errorf("the dump has no %q database file", DatabaseName)
	}

	return mainPath, nil
}

// HasState reports whether a node's state directory already holds dqlite data.
//
// Restoring is a disaster-recovery procedure that starts from a node with no
// data of its own (spec §7), so this is what stands between an operator and
// running it against a node that is still carrying the cluster.
func HasState(stateDir string) (bool, error) {
	entries, err := os.ReadDir(DataDir(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to inspect the cluster data directory: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			return true, nil
		}
	}

	return false, nil
}
