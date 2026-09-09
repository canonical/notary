package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db/migrations"
	"github.com/canonical/sqlair"
)

// Close closes the sqlair connection and the dqlite node.
func (db *DatabaseRepository) Close() error {
	var first error
	if db.Conn != nil {
		if err := db.Conn.PlainDB().Close(); err != nil {
			first = err
		}
		db.Conn = nil
		db.stmts = nil
	}
	if db.Node != nil {
		if err := db.Node.Close(); err != nil && first == nil {
			first = err
		}
		db.Node = nil
	}
	return first
}

// NewDatabase starts (or resumes) a dqlite node at DatabasePath and wraps it with sqlair.
func NewDatabase(dbOpts *DatabaseOpts) (*DatabaseRepository, error) {
	if dbOpts == nil {
		return nil, errors.New("database options are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var (
		sqlConnection *sql.DB
		node          *cluster.Node
		err           error
	)

	if dbOpts.DatabasePath == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(dbOpts.DatabasePath, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	node, err = cluster.Start(cluster.Options{
		Dir:       dbOpts.DatabasePath,
		Address:   dbOpts.Address,
		Name:      dbOpts.Name,
		Join:      dbOpts.Join,
		JoinToken: dbOpts.JoinToken,
		TLS:       dbOpts.clusterTLS(),
		TLSCert:   dbOpts.TLSCert,
		TLSKey:    dbOpts.TLSKey,
	})
	if err != nil {
		return nil, err
	}
	sqlConnection, err = node.Open(ctx)
	if err != nil {
		_ = node.Close()
		return nil, err
	}

	if _, err := sqlConnection.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		if node != nil {
			_ = sqlConnection.Close()
			_ = node.Close()
		}
		return nil, err
	}

	if err := migrations.Apply(ctx, sqlConnection); err != nil {
		if node != nil {
			_ = sqlConnection.Close()
			_ = node.Close()
		}
		return nil, fmt.Errorf("failed to apply schema updates: %w", err)
	}

	repo := new(DatabaseRepository)
	repo.stmts = PrepareStatements()
	repo.Conn = sqlair.NewDB(sqlConnection)
	repo.Path = dbOpts.DatabasePath
	repo.Node = node
	repo.ClusterTLS = node.TLS
	repo.TLSCert = dbOpts.TLSCert
	repo.TLSKey = dbOpts.TLSKey
	repo.HTTPSCert = dbOpts.HTTPSCert
	repo.APIAddress = dbOpts.APIAddress
	if _, isCA := node.TLS.(cluster.CAPeer); !isCA {
		if s, ok := node.TLS.(cluster.SharedPair); ok {
			repo.TLSCert, repo.TLSKey = s.Cert, s.Key
		} else if cert, key, err := cluster.LoadClusterTLS(dbOpts.DatabasePath); err == nil {
			repo.TLSCert, repo.TLSKey = cert, key
		}
	}

	name := dbOpts.Name
	if name == "" {
		name = cluster.DefaultMemberName()
	}
	if dbOpts.JoinToken != "" {
		token, err := cluster.DecodeJoinToken(dbOpts.JoinToken)
		if err != nil {
			_ = repo.Close()
			return nil, err
		}
		name = token.ServerName
	}
	if err := cluster.RegisterMember(ctx, sqlConnection, name, node.Address(), dbOpts.APIAddress); err != nil {
		if dbOpts.JoinToken != "" || len(dbOpts.Join) > 0 {
			_ = cluster.RemoveMemberOnNode(ctx, node, sqlConnection, node.Address())
		}
		_ = repo.Close()
		return nil, err
	}
	// Recovery rewrites raft membership without touching cluster_members, so drop
	// names that raft no longer knows or they block rejoining under the same name.
	if err := cluster.PruneMembers(ctx, node, sqlConnection); err != nil && dbOpts.Logger != nil {
		dbOpts.Logger.Sugar().Warnf("could not reconcile cluster member names: %s", err)
	}
	return repo, nil
}

func (o *DatabaseOpts) clusterTLS() cluster.TransportTLS {
	if o == nil {
		return nil
	}
	return o.ClusterTLS
}

// ListClusterMembers returns dqlite membership from the running node.
func (db *DatabaseRepository) ListClusterMembers(ctx context.Context) ([]cluster.Member, error) {
	if db == nil || db.Node == nil {
		return nil, fmt.Errorf("database is not open")
	}
	return db.Node.MembersWithNames(ctx, db.Conn.PlainDB())
}

// IssueJoinToken creates a one-time token for `notary cluster add <name>`.
func (db *DatabaseRepository) IssueJoinToken(ctx context.Context, name string) (string, error) {
	if db == nil || db.Node == nil {
		return "", fmt.Errorf("database is not open")
	}
	cert, key := db.TLSCert, db.TLSKey
	if db.ClusterTLS != nil {
		cert, key = cluster.PresentCertKey(db.ClusterTLS)
	}
	return cluster.IssueJoinTokenOnNode(ctx, db.Node, db.Conn.PlainDB(), name, cert, key, db.HTTPSCert, []string{db.APIAddress})
}

// RemoveClusterMember evicts a named member.
func (db *DatabaseRepository) RemoveClusterMember(ctx context.Context, name string) error {
	if db == nil || db.Node == nil {
		return fmt.Errorf("database is not open")
	}
	return cluster.RemoveMemberOnNode(ctx, db.Node, db.Conn.PlainDB(), name)
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
		if isUniqueConstraint(err) {
			return 0, fmt.Errorf("failed to create %s: %w: %w", getTypeName[T](), ErrAlreadyExists, err)
		}
		return 0, fmt.Errorf("failed to create %s: %w: %w", getTypeName[T](), ErrInternal, err)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %w: %w", getTypeName[T](), ErrInternal, err)
	}
	return insertedRowID, nil
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "UNIQUE constraint")
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
