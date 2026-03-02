package authorization

import (
	"context"
	"fmt"

	"github.com/canonical/notary/internal/db"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/assets"
	ofgaLogger "github.com/openfga/openfga/pkg/logger"
	ofgaServer "github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
	ofgaSqlite "github.com/openfga/openfga/pkg/storage/sqlite"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// AuthzRepository holds the OpenFGA server and store/model references.
type AuthzRepository struct {
	FGAClient            *ofgaServer.Server
	StoreID              string
	AuthorizationModelID string
}

// ObjectID formats an object ID for OpenFGA (e.g. "certificate_authority:3").
func ObjectID(objectType string, id int64) string {
	return fmt.Sprintf("%s:%d", objectType, id)
}

// UserID formats a user ID for OpenFGA (e.g. "user:admin@notary.local").
func UserID(email string) string {
	return fmt.Sprintf("user:%s", email)
}

// InitializeLocalOpenFGA initializes a local OpenFGA server backed by its own
// SQLite connection. dbPath is the filesystem path to the SQLite database.
func InitializeLocalOpenFGA(database *db.DatabaseRepository, logger *zap.Logger) (*AuthzRepository, error) {
	// Run OpenFGA's SQLite schema migrations on the shared DB connection.
	goose.SetLogger(goose.NopLogger())
	goose.SetBaseFS(assets.EmbedMigrations)
	if err := goose.SetDialect("sqlite"); err != nil {
		return nil, fmt.Errorf("failed to set goose dialect: %w", err)
	}
	if err := goose.Up(database.Conn.PlainDB(), assets.SqliteMigrationDir, goose.WithNoColor(true)); err != nil {
		return nil, fmt.Errorf("failed to run OpenFGA migrations: %w", err)
	}

	ofgaLog := &ofgaLogger.ZapLogger{Logger: logger}

	cfg := sqlcommon.NewConfig(
		sqlcommon.WithLogger(ofgaLog),
	)
	ds, err := ofgaSqlite.NewWithDB(database.Conn.PlainDB(), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA SQLite datastore: %w", err)
	}

	fga, err := ofgaServer.NewServerWithOpts(ofgaServer.WithDatastore(ds))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA server: %w", err)
	}

	stores, err := fga.ListStores(context.Background(), &openfgav1.ListStoresRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list OpenFGA stores: %w", err)
	}
	for _, store := range stores.Stores {
		if store.GetName() == "notary" {
			models, err := fga.ReadAuthorizationModels(context.Background(),
				&openfgav1.ReadAuthorizationModelsRequest{StoreId: store.Id})
			if err != nil || len(models.AuthorizationModels) == 0 {
				return nil, fmt.Errorf("failed to read OpenFGA authorization models: %v", err)
			}
			repo := &AuthzRepository{
				FGAClient:            fga,
				StoreID:              store.Id,
				AuthorizationModelID: models.AuthorizationModels[0].Id,
			}
			return repo, nil
		}
	}

	newStore, err := fga.CreateStore(context.Background(), &openfgav1.CreateStoreRequest{Name: "notary"})
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA store: %w", err)
	}

	protoModel, err := transformer.TransformDSLToProto(OFGAModel)
	if err != nil {
		return nil, fmt.Errorf("failed to transform OpenFGA DSL to proto: %w", err)
	}

	authModel, err := fga.WriteAuthorizationModel(context.Background(), &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         newStore.GetId(),
		TypeDefinitions: protoModel.GetTypeDefinitions(),
		Conditions:      protoModel.GetConditions(),
		SchemaVersion:   protoModel.GetSchemaVersion(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write OpenFGA authorization model: %w", err)
	}

	repo := &AuthzRepository{
		FGAClient:            fga,
		StoreID:              newStore.GetId(),
		AuthorizationModelID: authModel.GetAuthorizationModelId(),
	}

	// On fresh database initialization, seed the default admin tuple.
	if err := repo.WriteTuple("system:notary", "admin", "user:admin@notary.local"); err != nil {
		return nil, fmt.Errorf("failed to write default admin tuple: %w", err)
	}

	return repo, nil
}

func (r *AuthzRepository) WriteTuple(object, relation, user string) error {
	_, err := r.FGAClient.Write(context.Background(), &openfgav1.WriteRequest{
		StoreId:              r.StoreID,
		AuthorizationModelId: r.AuthorizationModelID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: []*openfgav1.TupleKey{
				{Object: object, Relation: relation, User: user},
			},
		},
	})
	return err
}

// DeleteTuple deletes a single relationship tuple.
func (r *AuthzRepository) DeleteTuple(object, relation, user string) error {
	_, err := r.FGAClient.Write(context.Background(), &openfgav1.WriteRequest{
		StoreId:              r.StoreID,
		AuthorizationModelId: r.AuthorizationModelID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: []*openfgav1.TupleKeyWithoutCondition{
				{Object: object, Relation: relation, User: user},
			},
		},
	})
	return err
}

// Check returns whether user has relation on object.
func (r *AuthzRepository) Check(object, relation, user string) (bool, error) {
	resp, err := r.FGAClient.Check(context.Background(), &openfgav1.CheckRequest{
		StoreId:              r.StoreID,
		AuthorizationModelId: r.AuthorizationModelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			Object:   object,
			Relation: relation,
			User:     user,
		},
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

// ListObjects returns all objects of objectType that user has relation on.
func (r *AuthzRepository) ListObjects(objectType, relation, user string) ([]string, error) {
	resp, err := r.FGAClient.ListObjects(context.Background(), &openfgav1.ListObjectsRequest{
		StoreId:              r.StoreID,
		AuthorizationModelId: r.AuthorizationModelID,
		Type:                 objectType,
		Relation:             relation,
		User:                 user,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetObjects(), nil
}
