package authorization

import (
	"context"
	"fmt"

	"github.com/canonical/notary/internal/db"
	"github.com/oklog/ulid/v2"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	ofgaLogger "github.com/openfga/openfga/pkg/logger"
	ofgaServer "github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
	ofgaSqlite "github.com/openfga/openfga/pkg/storage/sqlite"
	"go.uber.org/zap"
)

var dummyDatastoreULID = ulid.Make().String()

// AuthzRepository holds the OpenFGA server and mode
type AuthzRepository struct {
	FGAClient *ofgaServer.Server
	StoreID   string
}

// InitializeLocalOpenFGA initializes a local OpenFGA server with SQLite storage
// The OpenFGA datastore will automatically create its own tables and run migrations
// as needed when the datastore is first created.
func InitializeLocalOpenFGA(database *db.DatabaseRepository, logger *zap.Logger) (*AuthzRepository, error) {
	// Wrap the zap logger using OpenFGA's logger implementation
	ofgaLog := &ofgaLogger.ZapLogger{Logger: logger}

	// Create sqlcommon config for database connection
	cfg := sqlcommon.NewConfig(
		sqlcommon.WithLogger(ofgaLog),
	)
	// Make datastore from database
	ds, err := ofgaSqlite.NewWithDB(database.Conn.PlainDB(), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ofga Sqlite datastore: %s", err)
	}

	// start server with datastore
	openfga, err := ofgaServer.NewServerWithOpts(ofgaServer.WithDatastore(ds))
	if err != nil {
		return nil, fmt.Errorf("failed to create new ofga server: %s", err)
	}

	// if the store already exists, just return the server, otherwise create the store and write the model and tuples
	stores, err := openfga.ListStores(context.Background(), &openfgav1.ListStoresRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list stores: %s", err)
	}
	for _, store := range stores.Stores {
		if store.GetName() == "notary" {
			return &AuthzRepository{
				FGAClient: openfga,
				StoreID:   store.Id,
			}, nil
		}
	}

	newStore, err := openfga.CreateStore(context.Background(), &openfgav1.CreateStoreRequest{Name: "notary"})
	if err != nil {
		return nil, fmt.Errorf("failed to create notary openfga store: %s", err)
	}

	// transform dsl to proto
	protoModel, err := transformer.TransformDSLToProto(OFGAModel)
	if err != nil {
		return nil, fmt.Errorf("failed to transform dsl to proto: %s", err)
	}
	// write model to server
	authorizationModel, err := openfga.WriteAuthorizationModel(context.Background(), &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         newStore.GetId(),
		TypeDefinitions: protoModel.GetTypeDefinitions(),
		Conditions:      protoModel.GetConditions(),
		SchemaVersion:   protoModel.GetSchemaVersion(),
	})
	// write default admin tuple to server

	return &AuthzRepository{
		FGAClient: openfga,
		StoreID:   newStore.GetId(),
	}, nil
}
