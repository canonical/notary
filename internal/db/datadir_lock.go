package db

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const dqliteLockFile = "dqlite-lock"

var errDataDirInUse = errors.New("database directory is in use; stop the Notary daemon first")

// rejectIfDataDirInUse fails when a dqlite node still holds the data directory
// lock, which means notary start is running against this path.
//
// go-dqlite's C library creates a file named dqlite-lock in the data directory
// (not part of the Go API). If that name ever changes, os.IsNotExist below
// returns nil and this guard will not detect a live node.
func rejectIfDataDirInUse(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to access database directory: %w", err)
	}
	if !info.IsDir() {
		return nil
	}
	lockPath := filepath.Join(dataDir, dqliteLockFile)
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot check whether the database directory is in use: %w", err)
	}
	defer f.Close() //nolint:errcheck

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errDataDirInUse
		}
		return fmt.Errorf("cannot check whether the database directory is in use: %w", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return nil
}
