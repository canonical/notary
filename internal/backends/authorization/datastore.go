package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/storage"

	"github.com/canonical/notary/internal/db"
)

// errNotImplemented is returned by every datastore method notary never exercises.
// It is deliberately not a "storage" error the OpenFGA server knows how to
// recover from: reaching one of these methods means the server tried to use a
// feature notary's model does not have, which is a programming error.
var errNotImplemented = errors.New("not implemented by notary's authorization datastore")

// roleDatastore implements storage.OpenFGADatastore on top of notary's own
// users table. There is no OpenFGA-owned schema and no tuple store: the
// relationship tuples handed to the OpenFGA server are derived from
// users.role_id at read time, which is the single source of truth for a user's
// role. Consequently every write method is stubbed out — a role is granted by
// db.CreateUser/db.UpdateUserRole and by nothing else.
type roleDatastore struct {
	database *db.DatabaseRepository

	// model is the compiled-in OFGAModel. It is written once during
	// initialization, before the OpenFGA server is able to read it, and never
	// mutated afterwards.
	model *openfgav1.AuthorizationModel
}

// newRoleDatastore returns a datastore that answers authorization queries from
// the users table of the given database.
func newRoleDatastore(database *db.DatabaseRepository) *roleDatastore {
	return &roleDatastore{database: database}
}

// relationRoleIDs maps each relation in OFGAModel to the set of role IDs that
// satisfy it. This is RoleIDToRelation applied in reverse, with the model's
// hierarchy (admin ⊆ certificate_manager ⊆ certificate_requestor, and
// admin ⊆ certificate_manager ⊆ reader) already resolved.
//
// Resolving the hierarchy here rather than leaving it to the OpenFGA server is
// safe: the server unions these tuples with the same relations it computes
// itself, and union with an already-closed set is idempotent.
var relationRoleIDs = map[string][]db.RoleID{
	RelationAdmin:                {db.RoleAdmin},
	RelationCertificateManager:   {db.RoleAdmin, db.RoleCertificateManager},
	RelationCertificateRequestor: {db.RoleAdmin, db.RoleCertificateManager, db.RoleCertificateRequestor},
	RelationReader:               {db.RoleAdmin, db.RoleCertificateManager, db.RoleReadOnly},
}

// roleSatisfies reports whether a user holding roleID satisfies relation.
func roleSatisfies(relation string, roleID db.RoleID) bool {
	return slices.Contains(relationRoleIDs[relation], roleID)
}

// usersWithRelation returns the OpenFGA user IDs of every user whose role
// satisfies relation. An unknown relation yields no users rather than an error,
// so that a check against a relation outside the model simply fails closed.
func (d *roleDatastore) usersWithRelation(relation string) ([]string, error) {
	if _, ok := relationRoleIDs[relation]; !ok {
		return nil, nil
	}
	users, err := d.database.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	userIDs := make([]string, 0, len(users))
	for _, user := range users {
		if roleSatisfies(relation, user.RoleID) {
			userIDs = append(userIDs, UserID(user.Email))
		}
	}
	return userIDs, nil
}

// systemTuples builds the tuples relating the single system object to each of
// the given users via relation.
func systemTuples(relation string, userIDs []string) []*openfgav1.Tuple {
	tuples := make([]*openfgav1.Tuple, 0, len(userIDs))
	for _, userID := range userIDs {
		tuples = append(tuples, &openfgav1.Tuple{
			Key: &openfgav1.TupleKey{
				Object:   SystemObject,
				Relation: relation,
				User:     userID,
			},
		})
	}
	return tuples
}

// emailFromUserID extracts the email from an OpenFGA user ID such as
// "user:admin@notary.local". It reports false for anything that is not a plain
// user reference, including usersets ("user:x#member") and the type-bound
// wildcard ("user:*"), neither of which notary's model uses.
func emailFromUserID(userID string) (string, bool) {
	userType, email, ok := strings.Cut(userID, ":")
	if !ok || userType != userObjectType || email == "" {
		return "", false
	}
	if strings.ContainsAny(email, "#*") {
		return "", false
	}
	return email, true
}

// Read returns the tuples matching filter. Notary's model has a single object,
// so the only meaningful filters are on relation and user.
func (d *roleDatastore) Read(ctx context.Context, store string, filter storage.ReadFilter, options storage.ReadOptions) (storage.TupleIterator, error) {
	if filter.Object != "" && filter.Object != SystemObject {
		return storage.NewStaticTupleIterator(nil), nil
	}
	if filter.Relation == "" {
		return nil, errors.New("Read: a relation must be provided")
	}
	userIDs, err := d.usersWithRelation(filter.Relation)
	if err != nil {
		return nil, fmt.Errorf("Read: %w", err)
	}
	if filter.User != "" {
		if !slices.Contains(userIDs, filter.User) {
			return storage.NewStaticTupleIterator(nil), nil
		}
		userIDs = []string{filter.User}
	}
	return storage.NewStaticTupleIterator(systemTuples(filter.Relation, userIDs)), nil
}

// ReadUserTuple returns the single tuple matching filter exactly, which is the
// hot path for Check requests. It returns storage.ErrNotFound when the user's
// role does not satisfy the relation.
func (d *roleDatastore) ReadUserTuple(ctx context.Context, store string, filter storage.ReadUserTupleFilter, options storage.ReadUserTupleOptions) (*openfgav1.Tuple, error) {
	if filter.Object != SystemObject {
		return nil, storage.ErrNotFound
	}
	if _, ok := relationRoleIDs[filter.Relation]; !ok {
		return nil, storage.ErrNotFound
	}
	email, ok := emailFromUserID(filter.User)
	if !ok {
		return nil, storage.ErrNotFound
	}
	user, err := d.database.GetUser(db.ByEmail(email))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("ReadUserTuple: failed to get user: %w", err)
	}
	if !roleSatisfies(filter.Relation, user.RoleID) {
		return nil, storage.ErrNotFound
	}
	return &openfgav1.Tuple{
		Key: &openfgav1.TupleKey{
			Object:   SystemObject,
			Relation: filter.Relation,
			User:     filter.User,
		},
	}, nil
}

// ReadUsersetTuples returns the tuples whose user is itself a userset. Notary's
// model only ever assigns the concrete `user` type directly, so there are none.
func (d *roleDatastore) ReadUsersetTuples(ctx context.Context, store string, filter storage.ReadUsersetTuplesFilter, options storage.ReadUsersetTuplesOptions) (storage.TupleIterator, error) {
	return storage.NewStaticTupleIterator(nil), nil
}

// ReadStartingWithUser performs the reverse lookup used by ListObjects: given a
// user and a relation, which objects does the user have that relation on? There
// is only one object, so the answer is either that object or nothing.
func (d *roleDatastore) ReadStartingWithUser(ctx context.Context, store string, filter storage.ReadStartingWithUserFilter, options storage.ReadStartingWithUserOptions) (storage.TupleIterator, error) {
	if filter.ObjectType != systemObjectType {
		return storage.NewStaticTupleIterator(nil), nil
	}
	if _, ok := relationRoleIDs[filter.Relation]; !ok {
		return storage.NewStaticTupleIterator(nil), nil
	}
	if filter.ObjectIDs != nil && !filter.ObjectIDs.Exists(systemObjectID) {
		return storage.NewStaticTupleIterator(nil), nil
	}

	var tuples []*openfgav1.Tuple
	for _, userFilter := range filter.UserFilter {
		// A userset filter ("user:x#member") never matches: see ReadUsersetTuples.
		if userFilter.GetRelation() != "" {
			continue
		}
		email, ok := emailFromUserID(userFilter.GetObject())
		if !ok {
			continue
		}
		user, err := d.database.GetUser(db.ByEmail(email))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("ReadStartingWithUser: failed to get user: %w", err)
		}
		if !roleSatisfies(filter.Relation, user.RoleID) {
			continue
		}
		tuples = append(tuples, systemTuples(filter.Relation, []string{userFilter.GetObject()})...)
	}
	return storage.NewStaticTupleIterator(tuples), nil
}

// WriteAuthorizationModel stores the compiled-in model in memory.
func (d *roleDatastore) WriteAuthorizationModel(ctx context.Context, store string, model *openfgav1.AuthorizationModel) error {
	d.model = model
	return nil
}

// ReadAuthorizationModel returns the compiled-in model regardless of the
// requested ID: notary ships exactly one model and never versions it.
func (d *roleDatastore) ReadAuthorizationModel(ctx context.Context, store string, id string) (*openfgav1.AuthorizationModel, error) {
	if d.model == nil {
		return nil, storage.ErrNotFound
	}
	return d.model, nil
}

// FindLatestAuthorizationModel returns the compiled-in model.
func (d *roleDatastore) FindLatestAuthorizationModel(ctx context.Context, store string) (*openfgav1.AuthorizationModel, error) {
	if d.model == nil {
		return nil, storage.ErrNotFound
	}
	return d.model, nil
}

// ReadAuthorizationModels returns the compiled-in model as a single page.
func (d *roleDatastore) ReadAuthorizationModels(ctx context.Context, store string, options storage.ReadAuthorizationModelsOptions) ([]*openfgav1.AuthorizationModel, string, error) {
	if d.model == nil {
		return nil, "", storage.ErrNotFound
	}
	return []*openfgav1.AuthorizationModel{d.model}, "", nil
}

// MaxTypesPerAuthorizationModel returns OpenFGA's default. Notary's model has
// two types, so the exact value is immaterial.
func (d *roleDatastore) MaxTypesPerAuthorizationModel() int {
	return storage.DefaultMaxTypesPerAuthorizationModel
}

// MaxTuplesPerWrite returns -1: tuples are derived from users.role_id and are
// never written through this datastore.
func (d *roleDatastore) MaxTuplesPerWrite() int {
	return -1
}

// Write is not implemented. Role assignments are written by db.CreateUser and
// db.UpdateUserRole; allowing a tuple write here would reintroduce a second,
// divergent source of truth.
func (d *roleDatastore) Write(ctx context.Context, store string, deletes storage.Deletes, writes storage.Writes, opts ...storage.TupleWriteOption) error {
	return errNotImplemented
}

// ReadPage is not implemented: notary never paginates tuples.
func (d *roleDatastore) ReadPage(ctx context.Context, store string, filter storage.ReadFilter, options storage.ReadPageOptions) ([]*openfgav1.Tuple, string, error) {
	return nil, "", errNotImplemented
}

// CreateStore is not implemented: there is exactly one store, storeID.
func (d *roleDatastore) CreateStore(ctx context.Context, store *openfgav1.Store) (*openfgav1.Store, error) {
	return nil, errNotImplemented
}

// DeleteStore is not implemented: there is exactly one store, storeID.
func (d *roleDatastore) DeleteStore(ctx context.Context, id string) error {
	return errNotImplemented
}

// GetStore is not implemented: there is exactly one store, storeID.
func (d *roleDatastore) GetStore(ctx context.Context, id string) (*openfgav1.Store, error) {
	return nil, errNotImplemented
}

// ListStores is not implemented: there is exactly one store, storeID.
func (d *roleDatastore) ListStores(ctx context.Context, options storage.ListStoresOptions) ([]*openfgav1.Store, string, error) {
	return nil, "", errNotImplemented
}

// WriteAssertions is not implemented: notary does not use the assertions API.
func (d *roleDatastore) WriteAssertions(ctx context.Context, store, modelID string, assertions []*openfgav1.Assertion) error {
	return errNotImplemented
}

// ReadAssertions is not implemented: notary does not use the assertions API.
func (d *roleDatastore) ReadAssertions(ctx context.Context, store, modelID string) ([]*openfgav1.Assertion, error) {
	return nil, errNotImplemented
}

// ReadChanges is not implemented: there is no changelog to read, since tuples
// are derived rather than written.
func (d *roleDatastore) ReadChanges(ctx context.Context, store string, filter storage.ReadChangesFilter, options storage.ReadChangesOptions) ([]*openfgav1.TupleChange, string, error) {
	return nil, "", errNotImplemented
}

// IsReady reports the datastore as ready. Readiness of the underlying database
// is reported through notary's own status endpoint, not through OpenFGA.
func (d *roleDatastore) IsReady(ctx context.Context) (storage.ReadinessStatus, error) {
	return storage.ReadinessStatus{IsReady: true}, nil
}

// Close is a no-op: the database connection is owned by notary, not by OpenFGA.
func (d *roleDatastore) Close() {}
