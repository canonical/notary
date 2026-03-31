// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/canonical/notary/internal/db/migrations"
	"github.com/canonical/sqlair"
	"github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// Close closes the connection to the repository cleanly.
func (db *DatabaseRepository) Close() error {
	if db.Conn == nil {
		return nil
	}
	if err := db.Conn.PlainDB().Close(); err != nil {
		return err
	}
	db.stmts = nil
	return nil
}

// NewDatabase connects to a given table in a given database,
// stores the connection information and returns an object containing the information.
// The database path must be a valid file path or ":memory:".
// The table will be created if it doesn't exist in the format expected by the package.
func NewDatabase(dbOpts *DatabaseOpts) (*DatabaseRepository, error) {
	sqlConnection, err := sql.Open("sqlite", dbOpts.DatabasePath)
	if err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, err
	}
	sqlConnection.SetMaxIdleConns(2)
	sqlConnection.SetMaxOpenConns(2)
	err = goose.SetDialect("sqlite")
	if err != nil {
		return nil, err
	}
	version, err := goose.EnsureDBVersion(sqlConnection)
	if err != nil {
		return nil, err
	}
	if version < 1 {
		if dbOpts.ApplyMigrations {
			goose.SetBaseFS(migrations.EmbedMigrations)
			if err := goose.Up(sqlConnection, ".", goose.WithNoColor(true)); err != nil {
				return nil, fmt.Errorf("failed to apply migrations: %w", err)
			}
		} else {
			return nil, errors.New("database migrations not applied. please migrate database using `notary migrate up`")
		}
	}
	db := new(DatabaseRepository)
	db.stmts = PrepareStatements()
	db.Conn = sqlair.NewDB(sqlConnection)
	db.Path = dbOpts.DatabasePath

	// Create default admin account if no users exist
	users, err := db.ListUsers()
	if err != nil && err != ErrNotFound {
		return nil, fmt.Errorf("failed to check for existing users: %w", err)
	}
	if len(users) == 0 {
		if err := createDefaultAdminUser(db); err != nil {
			return nil, fmt.Errorf("failed to create default admin user: %w", err)
		}
	}

	return db, nil
}

// createDefaultAdminUser creates a default admin account with a known username and password
// This account should be used to bootstrap the system and then change the password
// TODO: this should have a randomly generated password
func createDefaultAdminUser(db *DatabaseRepository) error {
	// Check if any admin users already exist
	users, err := db.ListUsers()
	if err != nil && err != ErrNotFound {
		return err
	}
	if len(users) > 0 {
		// Users already exist, skip creation
		return nil
	}

	// Create default admin user
	const defaultAdminEmail = "admin@notary.local"
	const defaultAdminPassword = "admin"

	_, err = db.CreateUser(defaultAdminEmail, defaultAdminPassword, RoleAdmin)
	if err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	return nil
}

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *DatabaseRepository, stmt *sqlair.Statement, inputArgs ...any) ([]T, error) {
	var entities []T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, fmt.Errorf("failed to list %s: %w", getTypeName[T](), ErrInternal)
	}
	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, inputArgs ...any) (*T, error) {
	var result T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).Get(&result)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("failed to get %s: %w", getTypeName[T](), ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get %s: %w", getTypeName[T](), ErrInternal)
	}

	return &result, nil
}

func CreateEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, new_entity T) (int64, error) {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, new_entity).Get(&outcome)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrAlreadyExists)
		}
		return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrInternal)
	}
	return insertedRowID, nil
}

func UpdateEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, updated_entity T) error {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, updated_entity).Get(&outcome)
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrInternal)
	}
	affectedRows, err := outcome.Result().RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrInternal)
	}
	if affectedRows == 0 {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrNotFound)
	}
	return nil
}

func DeleteEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, entity_to_delete T) error {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, entity_to_delete).Get(&outcome)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrInternal)
	}
	affectedRows, err := outcome.Result().RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrInternal)
	}
	if affectedRows == 0 {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrNotFound)
	}
	return nil
}

// CreateBackup creates a compressed archive of the database and returns the archive path.
func CreateBackup(db *DatabaseRepository, backupDir string) (string, error) {
	timestamp := time.Now().UTC().Format("20060102_150405")
	backupFileName := fmt.Sprintf("notary_backup_%s.db", timestamp)
	backupPath := filepath.Join(backupDir, backupFileName)
	archivePath := filepath.Join(backupDir, fmt.Sprintf("backup_%s.tar.gz", timestamp))

	vacuumQuery := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(backupPath, "'", "''"))
	if _, err := db.Conn.PlainDB().ExecContext(context.Background(), vacuumQuery); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}
	defer os.Remove(backupPath) //nolint:errcheck

	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to create archive: %w", err)
	}
	defer archiveFile.Close() //nolint:errcheck

	gzWriter := gzip.NewWriter(archiveFile)
	defer gzWriter.Close() //nolint:errcheck

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close() //nolint:errcheck

	backupFile, err := os.Open(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to open backup: %w", err)
	}
	defer backupFile.Close() //nolint:errcheck

	stat, err := backupFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat backup: %w", err)
	}

	header := &tar.Header{
		Name:    backupFileName,
		Mode:    0600,
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return "", fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := io.Copy(tarWriter, backupFile); err != nil {
		return "", fmt.Errorf("failed to write tar contents: %w", err)
	}

	return archivePath, nil
}

func RestoreBackup(db *DatabaseRepository, archivePath string) error {
	absPath, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("failed to resolve archive path %q: %w", archivePath, err)
	}

	if _, err := os.Stat(absPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup archive not found at %q", absPath)
		}
		return fmt.Errorf("cannot access backup archive at %q: %w", absPath, err)
	}

	archivePath = absPath

	if db.Path == "" || db.Path == ":memory:" {
		return errors.New("cannot restore to in-memory database")
	}

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

	_, err = tarReader.Next()
	if err != nil {
		return fmt.Errorf("failed to read archive contents: %w", err)
	}

	tempDir := os.TempDir()
	tempDBPath := filepath.Join(tempDir, fmt.Sprintf("restore_%d.db", time.Now().UnixNano()))

	tempFile, err := os.Create(tempDBPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		tempFile.Close()      //nolint:errcheck
		os.Remove(tempDBPath) //nolint:errcheck
	}()

	if _, err := io.Copy(tempFile, tarReader); err != nil {
		return fmt.Errorf("failed to extract database: %w", err)
	}
	tempFile.Close() //nolint:errcheck

	backupDB, err := sql.Open("sqlite3", tempDBPath)
	if err != nil {
		return fmt.Errorf("invalid database file: %w", err)
	}
	if err := backupDB.Ping(); err != nil {
		backupDB.Close() //nolint:errcheck
		return fmt.Errorf("backup file is not a valid database: %w", err)
	}

	destDB, err := sql.Open("sqlite3", db.Path)
	if err != nil {
		backupDB.Close() //nolint:errcheck
		return fmt.Errorf("failed to open destination database: %w", err)
	}
	defer destDB.Close() //nolint:errcheck

	ctx := context.Background()
	destConn, err := destDB.Conn(ctx)
	if err != nil {
		backupDB.Close() //nolint:errcheck
		return fmt.Errorf("failed to get destination connection: %w", err)
	}
	defer destConn.Close() //nolint:errcheck

	srcConn, err := backupDB.Conn(ctx)
	if err != nil {
		backupDB.Close() //nolint:errcheck
		return fmt.Errorf("failed to get source connection: %w", err)
	}
	defer srcConn.Close() //nolint:errcheck

	err = destConn.Raw(func(destRaw any) error {
		return srcConn.Raw(func(srcRaw any) error {
			destSQLite, ok := destRaw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("destination is not a SQLite connection")
			}
			srcSQLite, ok := srcRaw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("source is not a SQLite connection")
			}

			backup, err := destSQLite.Backup("main", srcSQLite, "main")
			if err != nil {
				return fmt.Errorf("failed to initialize backup: %w", err)
			}

			isDone, err := backup.Step(-1)
			if err != nil {
				if finishErr := backup.Finish(); finishErr != nil {
					return fmt.Errorf("backup step failed: %w (cleanup error: %v)", err, finishErr)
				}
				return fmt.Errorf("backup step failed: %w", err)
			}
			if !isDone {
				if finishErr := backup.Finish(); finishErr != nil {
					return fmt.Errorf("backup incomplete (cleanup error: %v)", finishErr)
				}
				return errors.New("backup incomplete")
			}

			if err := backup.Finish(); err != nil {
				return fmt.Errorf("failed to finalize backup: %w", err)
			}

			return nil
		})
	})

	backupDB.Close() //nolint:errcheck

	if err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	return nil
}
