package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/canonical/notary/internal/db"
	ofgaLogger "github.com/openfga/openfga/pkg/logger"
	ofgaServer "github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
	"github.com/openfga/openfga/pkg/storage/sqlite"
	"go.uber.org/zap"
)

// AuthorizationMode represents the mode of authorization
type AuthorizationMode string

const (
	AuthorizationModeLocal  AuthorizationMode = "local"
	AuthorizationModeRemote AuthorizationMode = "remote"
)

// OpenFGARepository holds the OpenFGA server and mode
type OpenFGARepository struct {
	Mode      AuthorizationMode
	FGAClient *ofgaServer.Server
}

// InitializeLocalOpenFGA initializes a local OpenFGA server with SQLite storage
// The OpenFGA datastore will automatically create its own tables and run migrations
// as needed when the datastore is first created.
func InitializeLocalOpenFGA(database *db.DatabaseRepository, logger *zap.Logger) (*OpenFGARepository, error) {
	// Wrap the zap logger using OpenFGA's logger implementation
	ofgaLog := &ofgaLogger.ZapLogger{Logger: logger}

	// Get the raw SQL connection from the notary database
	sqlConn := database.Conn.PlainDB()

	// Create OpenFGA SQLite datastore configuration
	config := sqlcommon.NewConfig(
		sqlcommon.WithLogger(ofgaLog),
	)

	// Create the SQLite datastore using the notary database connection
	datastore, err := sqlite.NewWithDB(sqlConn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA SQLite datastore: %w", err)
	}

	// Check if the datastore is ready (will run migrations if needed)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	readinessStatus, err := datastore.IsReady(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check OpenFGA datastore readiness: %w", err)
	}

	if !readinessStatus.IsReady {
		return nil, fmt.Errorf("OpenFGA datastore is not ready: %s", readinessStatus.Message)
	}

	// Create the OpenFGA server with the SQLite datastore
	server, err := ofgaServer.NewServerWithOpts(
		ofgaServer.WithDatastore(datastore),
		ofgaServer.WithLogger(ofgaLog),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA server: %w", err)
	}

	logger.Info("OpenFGA local server initialized successfully with SQLite storage")

	return &OpenFGARepository{
		Mode:      AuthorizationModeLocal,
		FGAClient: server,
	}, nil
}
