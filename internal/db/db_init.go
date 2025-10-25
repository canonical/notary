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
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

// Close closes the connection to the repository cleanly.
func (db *Database) Close() error {
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
func NewDatabase(dbOpts *DatabaseOpts) (*Database, error) {
	sqlConnection, err := sql.Open("sqlite3", dbOpts.DatabasePath)
	if err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, err
	}
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
	db := new(Database)
	db.stmts = PrepareStatements()
	db.Conn = sqlair.NewDB(sqlConnection)
	db.Path = dbOpts.DatabasePath

	db.EncryptionKey, err = setUpEncryptionKey(db, dbOpts.Backend, dbOpts.Logger)
	if err != nil {
		return nil, err
	}
	db.JWTSecret, err = setUpJWTSecret(db)
	if err != nil {
		return nil, fmt.Errorf("failed to set up JWT secret: %w", err)
	}

	return db, nil
}

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *Database, stmt *sqlair.Statement, inputArgs ...any) ([]T, error) {
	var entities []T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, fmt.Errorf("failed to list %s: %w", getTypeName[T](), ErrInternal)
	}
	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *Database, stmt *sqlair.Statement, inputArgs ...any) (*T, error) {
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

func CreateEntity[T any](db *Database, stmt *sqlair.Statement, new_entity T) (int64, error) {
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

func UpdateEntity[T any](db *Database, stmt *sqlair.Statement, updated_entity T) error {
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

func DeleteEntity[T any](db *Database, stmt *sqlair.Statement, entity_to_delete T) error {
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


func CreateBackup(db *Database, backupDir string) error {
	timestamp := time.Now().UTC().Format("20060102_150405")
	backupFileName := fmt.Sprintf("notary_backup_%s.db", timestamp)
	backupPath := filepath.Join(backupDir, backupFileName)
	archivePath := filepath.Join(backupDir, fmt.Sprintf("backup_%s.tar.gz", timestamp))

	vacuumQuery := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(backupPath, "'", "''"))
	if _, err := db.Conn.PlainDB().ExecContext(context.Background(), vacuumQuery); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	defer os.Remove(backupPath)

	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	defer archiveFile.Close()

	gzWriter := gzip.NewWriter(archiveFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	backupFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup: %w", err)
	}
	defer backupFile.Close()

	stat, err := backupFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat backup: %w", err)
	}

	header := &tar.Header{
		Name:    backupFileName,
		Mode:    0600,
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := io.Copy(tarWriter, backupFile); err != nil {
		return fmt.Errorf("failed to write tar contents: %w", err)
	}

	return nil
}

func RestoreBackup(db *Database, archivePath string) error {
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("backup archive not found: %w", err)
	}

	if db.Path == "" || db.Path == ":memory:" {
		return errors.New("cannot restore to in-memory database")
	}

	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close()

	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return fmt.Errorf("failed to decompress archive: %w", err)
	}
	defer gzReader.Close()

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
		tempFile.Close()
		os.Remove(tempDBPath)
	}()

	if _, err := io.Copy(tempFile, tarReader); err != nil {
		return fmt.Errorf("failed to extract database: %w", err)
	}
	tempFile.Close()

	testDB, err := sql.Open("sqlite3", tempDBPath)
	if err != nil {
		return fmt.Errorf("invalid database file: %w", err)
	}
	if err := testDB.Ping(); err != nil {
		testDB.Close()
		return fmt.Errorf("backup file is not a valid database: %w", err)
	}
	testDB.Close()

	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close current database: %w", err)
	}

	if err := os.Remove(db.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove current database: %w", err)
	}

	if err := os.Rename(tempDBPath, db.Path); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	return nil
}

