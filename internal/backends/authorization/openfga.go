package authorization

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	ofgaServer "github.com/openfga/openfga/pkg/server"
	"go.uber.org/zap"

	"github.com/canonical/notary/internal/db"
)

// Object names used throughout notary's authorization model. The model (see
// schema.go) has exactly one object, so these are constants rather than
// anything derived at runtime.
const (
	systemObjectType = "system"
	systemObjectID   = "notary"
	userObjectType   = "user"

	// SystemObject is the single object every authorization check is made against.
	SystemObject = systemObjectType + ":" + systemObjectID
)

// Relation names on SystemObject. These mirror the relations declared in
// OFGAModel; internal/server maps notary role IDs onto them.
const (
	RelationAdmin                = "admin"
	RelationCertificateManager   = "certificate_manager"
	RelationCertificateRequestor = "certificate_requestor"
	RelationReader               = "reader"
)

// storeID and modelID identify the single store and the single authorization
// model notary uses. The OpenFGA server requires both to be ULIDs, but since
// neither is ever created or enumerated at runtime, they are fixed constants
// rather than generated values.
const (
	storeID = "01HQ5J8B0K7Z4XW2M9NCTVDFGR"
	modelID = "01HQ5J8B0K7Z4XW2M9NCTVDFGS"
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
// Returns "" if email is empty, so callers that check authorization with an
// empty userID will fail the check gracefully (resulting in a 403).
func UserID(email string) string {
	if email == "" {
		return ""
	}
	return userObjectType + ":" + email
}

// InitializeLocalOpenFGA initializes a local OpenFGA server that evaluates
// notary's compiled-in authorization model against notary's own users table.
//
// OpenFGA's storage layer is not used: no OpenFGA-owned schema is created, no
// migrations are run, and no tuples are persisted anywhere. Relationship tuples
// are derived from users.role_id on demand by roleDatastore, which keeps role
// assignment single-sourced in the users table.
func InitializeLocalOpenFGA(database *db.DatabaseRepository, logger *zap.Logger) (*AuthzRepository, error) {
	protoModel, err := transformer.TransformDSLToProto(OFGAModel)
	if err != nil {
		return nil, fmt.Errorf("failed to transform OpenFGA DSL to proto: %w", err)
	}
	protoModel.Id = modelID

	datastore := newRoleDatastore(database)
	// The model is loaded before the server exists, so no request can ever
	// observe the datastore without one.
	if err := datastore.WriteAuthorizationModel(context.Background(), storeID, protoModel); err != nil {
		return nil, fmt.Errorf("failed to load OpenFGA authorization model: %w", err)
	}

	fga, err := ofgaServer.NewServerWithOpts(ofgaServer.WithDatastore(datastore))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA server: %w", err)
	}
	logger.Info("Initialized OpenFGA authorization backend", zap.String("model_id", modelID))

	return &AuthzRepository{
		FGAClient:            fga,
		StoreID:              storeID,
		AuthorizationModelID: modelID,
	}, nil
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
