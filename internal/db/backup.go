package db

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CreateBackup archives the dqlite data directory into backupDir and returns
// the path of the tar.gz. Notary must be stopped so the files are consistent.
func CreateBackup(dataDir, backupDir string) (string, error) {
	if dataDir == "" {
		return "", errors.New("database directory is required")
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		return "", fmt.Errorf("failed to access database directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("database path is not a directory: %s", dataDir)
	}

	dataAbs, err := resolveExistingDir(dataDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve database directory: %w", err)
	}
	backupAbs, err := resolveExistingDir(backupDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve backup directory: %w", err)
	}
	if err := rejectBackupInsideDataDir(dataAbs, backupAbs); err != nil {
		return "", err
	}

	archiveFile, archivePath, err := createUniqueBackupFile(backupAbs)
	if err != nil {
		return "", err
	}
	succeeded := false
	defer func() {
		_ = archiveFile.Close()
		if !succeeded {
			_ = os.Remove(archivePath)
		}
	}()
	archiveInfo, err := archiveFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat backup archive: %w", err)
	}

	gzWriter := gzip.NewWriter(archiveFile)
	tarWriter := tar.NewWriter(gzWriter)

	err = filepath.Walk(dataAbs, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if os.SameFile(archiveInfo, fi) {
			return nil
		}
		rel, err := filepath.Rel(dataAbs, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, f)
		_ = f.Close()
		return copyErr
	})
	if err != nil {
		_ = tarWriter.Close()
		_ = gzWriter.Close()
		return "", fmt.Errorf("failed to write backup archive: %w", err)
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzWriter.Close()
		return "", fmt.Errorf("failed to close tar archive: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close gzip archive: %w", err)
	}
	succeeded = true
	return archivePath, nil
}

func resolveExistingDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func rejectBackupInsideDataDir(dataAbs, backupAbs string) error {
	rel, err := filepath.Rel(dataAbs, backupAbs)
	if err != nil {
		return fmt.Errorf("failed to compare backup and database paths: %w", err)
	}
	if rel == "." || filepath.IsLocal(rel) {
		return fmt.Errorf("backup directory %q is inside the database directory %q", backupAbs, dataAbs)
	}
	return nil
}

func createUniqueBackupFile(backupDir string) (*os.File, string, error) {
	const attempts = 100
	for range attempts {
		name := fmt.Sprintf("backup_%s.tar.gz", time.Now().UTC().Format("20060102_150405.000000000"))
		archivePath := filepath.Join(backupDir, name)
		f, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return f, archivePath, nil
		}
		if !os.IsExist(err) {
			return nil, "", fmt.Errorf("failed to create archive: %w", err)
		}
	}
	return nil, "", errors.New("failed to allocate a unique backup filename")
}

// RestoreBackup replaces the data directory with the contents of a backup
// archive created by CreateBackup. Notary must be stopped.
func RestoreBackup(dataDir, archivePath string) error {
	if dataDir == "" {
		return errors.New("database directory is required")
	}
	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("failed to resolve archive path %q: %w", archivePath, err)
	}
	if _, err := os.Stat(absArchive); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup archive not found at %q", absArchive)
		}
		return fmt.Errorf("cannot access backup archive at %q: %w", absArchive, err)
	}

	parent := filepath.Dir(dataDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("failed to create database parent directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(parent, "notary-restore-*")
	if err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	if err := extractBackupArchive(absArchive, tmpDir); err != nil {
		return err
	}

	if err := os.RemoveAll(dataDir); err != nil {
		return fmt.Errorf("failed to replace database directory: %w", err)
	}
	if err := os.Rename(tmpDir, dataDir); err != nil {
		return fmt.Errorf("failed to move restored database into place: %w", err)
	}
	return nil
}

func extractBackupArchive(archivePath, destDir string) error {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close() //nolint:errcheck

	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return fmt.Errorf("failed to decompress archive: %w", err)
	}
	defer gzReader.Close() //nolint:errcheck

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read archive contents: %w", err)
		}
		if err := extractTarEntry(destDir, header, tarReader); err != nil {
			return err
		}
	}
	return nil
}

func extractTarEntry(destDir string, header *tar.Header, r io.Reader) error {
	name := filepath.Clean(header.Name)
	if name == "." || name == string(filepath.Separator) {
		return nil
	}
	if strings.HasPrefix(name, "..") || strings.Contains(name, "/../") {
		return fmt.Errorf("invalid path in archive: %s", header.Name)
	}
	target := filepath.Join(destDir, name)
	if !strings.HasPrefix(target, destDir+string(os.PathSeparator)) && target != destDir {
		return fmt.Errorf("invalid path in archive: %s", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, 0o700)
	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	default:
		return nil
	}
}
