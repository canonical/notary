package testutils

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/canonical/notary/internal/acme"
	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func MustPrepareEmptyDB(t *testing.T) *db.DatabaseRepository {
	t.Helper()

	database := mustOpenTestDatabase(t)

	// Set up encryption key for the database
	encryptionBackend := &encryption.NoEncryptionBackend{}
	err := encryption.SetUpEncryptionKey(database, encryptionBackend, logger)
	if err != nil {
		t.Fatalf("Couldn't set up encryption key: %s", err)
	}

	// Set up JWT secret for the database
	err = authentication.SetUpJWTSecret(database)
	if err != nil {
		t.Fatalf("Couldn't set up JWT secret: %s", err)
	}

	t.Cleanup(func() {
		err := database.Close()
		if err != nil {
			t.Fatalf("Couldn't close database: %s", err)
		}
	})
	return database
}

// ClusteredTestsEnvVar makes the shared test fixtures run against a single-node
// dqlite cluster instead of a local SQLite file. It exists so the entire
// existing suite can be replayed, unmodified, against the clustered storage
// path — the regression gate for the storage engine swap.
//
// It is opt-in because dqlite is Linux-only and starting a node per test is
// considerably slower than opening a file.
const ClusteredTestsEnvVar = "NOTARY_TEST_DQLITE"

func mustOpenTestDatabase(t *testing.T) *db.DatabaseRepository {
	t.Helper()

	if os.Getenv(ClusteredTestsEnvVar) == "" {
		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath:    filepath.Join(t.TempDir(), "db.sqlite"),
			ApplyMigrations: true,
			Logger:          logger,
		})
		if err != nil {
			t.Fatalf("Couldn't complete NewDatabase: %s", err)
		}
		return database
	}

	return mustOpenClusteredTestDatabase(t)
}

// mustOpenClusteredTestDatabase starts a single-node dqlite cluster for the
// duration of the test and returns a repository backed by it.
//
// Only one node runs at a time per process, serialized by clusteredTestLock.
// Across processes, `go test` runs packages in parallel, and go-dqlite derives
// the abstract unix socket its node listens on from the node ID (app/app.go).
// A bootstrapping node always uses the constant dqlite.BootstrapID, so every
// test binary would ask for the same socket name; abstract sockets are global to
// the network namespace, so all but one would fail to bind. isolateDqliteSocket
// gives this process its own name.
func mustOpenClusteredTestDatabase(t *testing.T) *db.DatabaseRepository {
	t.Helper()

	isolateDqliteSocket(t)

	clusteredTestLock.Lock()
	var node cluster.Node
	t.Cleanup(func() {
		defer clusteredTestLock.Unlock()
		if node == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), clusteredTestTimeout)
		defer cancel()
		if err := node.Close(ctx); err != nil {
			t.Errorf("Couldn't close cluster node: %s", err)
		}
	})

	node, err := cluster.Start(cluster.Options{
		StateDir: t.TempDir(),
		Address:  mustReserveLoopbackAddress(t),
		// A fresh temporary directory every time, so this is always a bootstrap.
		Bootstrap: true,
	})
	if err != nil {
		t.Fatalf("Couldn't start cluster node: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), clusteredTestTimeout)
	defer cancel()

	if err := node.Ready(ctx); err != nil {
		t.Fatalf("Cluster node never became ready: %s", err)
	}
	conn, err := node.Open(ctx, cluster.DatabaseName)
	if err != nil {
		t.Fatalf("Couldn't open clustered database: %s", err)
	}
	database, err := db.NewDatabaseFromConn(conn, &db.DatabaseOpts{
		DatabasePath:    cluster.DatabaseName,
		ApplyMigrations: true,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabaseFromConn: %s", err)
	}

	return database
}

const (
	clusteredTestTimeout = 30 * time.Second
)

// clusteredTestLock serializes clustered fixtures so at most one dqlite node is
// alive in the process at a time.
var clusteredTestLock sync.Mutex

var isolateDqliteSocketOnce sync.Once

// isolateDqliteSocket gives this test binary its own abstract socket name for
// the dqlite node, so test packages running in parallel do not fight over the
// single name a bootstrapping node would otherwise pick.
//
// SNAP_INSTANCE_NAME is the only knob go-dqlite exposes over that name: it
// prefixes the socket with the snap instance so AppArmor lets it through
// (app/app.go). Nothing else in Notary reads it, and it is set only under
// ClusteredTestsEnvVar.
func isolateDqliteSocket(t *testing.T) {
	t.Helper()

	isolateDqliteSocketOnce.Do(func() {
		if err := os.Setenv("SNAP_INSTANCE_NAME", fmt.Sprintf("notary-test-%d", os.Getpid())); err != nil {
			t.Fatalf("Couldn't isolate the dqlite socket name: %s", err)
		}
	})
}

// mustReserveLoopbackAddress returns a loopback address with a port that was
// free a moment ago. dqlite needs a concrete advertised address, so the port
// cannot simply be zero.
func mustReserveLoopbackAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Couldn't reserve a port: %s", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("Couldn't release reserved port: %s", err)
	}

	return address
}

var logger, _ = zap.NewDevelopment()

// MustCreateTestAppConfig creates a test AppConfig with reasonable defaults
func MustCreateTestAppConfig(t *testing.T) *config.AppConfig {
	t.Helper()

	// Create a default logging config using viper
	loggingConfig := viper.New()
	loggingConfig.SetDefault("system.output", "stdout")
	loggingConfig.SetDefault("system.level", "info")
	loggingConfig.SetDefault("audit.output", "stdout")
	loggingConfig.SetDefault("audit.level", "info")

	return &config.AppConfig{
		Port:                            8000,
		ExternalHostname:                "example.com",
		DBPath:                          ":memory:",
		ShouldApplyMigrations:           false,
		ShouldEnablePebbleNotifications: false,
		TLSCertificate:                  []byte(TestServerCertificate),
		TLSPrivateKey:                   []byte(TestServerKey),
		LoggingConfig:                   loggingConfig,
	}
}

// MustCreateTestAppEnvironment creates a test AppEnvironment with reasonable defaults
func MustCreateTestAppEnvironment(t *testing.T, database *db.DatabaseRepository) *config.AppEnvironment {
	t.Helper()
	encryptionRepo := &encryption.EncryptionRepository{
		Type:      encryption.EncryptionBackendTypeNone,
		Service:   &encryption.NoEncryptionBackend{},
		SealState: encryption.NewSealState(),
	}

	// Set up the encryption key in the database
	err := encryption.SetUpEncryptionKey(database, encryptionRepo.Service, logger)
	if err != nil {
		t.Fatalf("failed to set up encryption key: %s", err)
	}
	encryptionRepo.SealState.Unseal()

	authzRepo, err := authorization.InitializeLocalOpenFGA(database, logger)
	if err != nil {
		t.Fatalf("failed to initialize OpenFGA: %s", err)
	}

	acmeReconciler := acme.NewReconciler()
	acmeReconciler.Attach(database, logger, "")

	return &config.AppEnvironment{
		Database:             database,
		SystemLogger:         logger,
		AuditLogger:          nil, // Can be set up as needed
		EncryptionRepository: encryptionRepo,
		AuthzRepository:      authzRepo,
		ACMEReconciler:       acmeReconciler,
	}
}
