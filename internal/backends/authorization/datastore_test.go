package authorization_test

import (
	"slices"
	"testing"

	"go.uber.org/zap"

	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

// mustInitAuthz returns an authorization repository backed by a fresh database.
func mustInitAuthz(t *testing.T) (*authorization.AuthzRepository, *db.DatabaseRepository) {
	t.Helper()
	database := tu.MustPrepareEmptyDB(t)
	repo, err := authorization.InitializeLocalOpenFGA(database, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to initialize OpenFGA: %s", err)
	}
	return repo, database
}

func mustCreateUser(t *testing.T, database *db.DatabaseRepository, email string, roleID db.RoleID) int64 {
	t.Helper()
	id, err := database.CreateUser(email, "Nzt5G@r0m1sVA!p", roleID)
	if err != nil {
		t.Fatalf("failed to create user %q: %s", email, err)
	}
	return id
}

// allRelations is every relation declared in OFGAModel.
var allRelations = []string{
	authorization.RelationAdmin,
	authorization.RelationCertificateManager,
	authorization.RelationCertificateRequestor,
	authorization.RelationReader,
}

// TestCheckResolvesTheFullRoleHierarchy asserts that a Check against every
// relation in the model returns the result implied by the user's role_id alone,
// including the relations a role inherits rather than holds directly.
func TestCheckResolvesTheFullRoleHierarchy(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		roleID  db.RoleID
		granted []string
	}{
		{
			name:   "admin inherits every relation",
			email:  "admin@canonical.com",
			roleID: db.RoleAdmin,
			granted: []string{
				authorization.RelationAdmin,
				authorization.RelationCertificateManager,
				authorization.RelationCertificateRequestor,
				authorization.RelationReader,
			},
		},
		{
			name:   "certificate manager inherits everything below admin",
			email:  "manager@canonical.com",
			roleID: db.RoleCertificateManager,
			granted: []string{
				authorization.RelationCertificateManager,
				authorization.RelationCertificateRequestor,
				authorization.RelationReader,
			},
		},
		{
			name:    "certificate requestor holds only its own relation",
			email:   "requestor@canonical.com",
			roleID:  db.RoleCertificateRequestor,
			granted: []string{authorization.RelationCertificateRequestor},
		},
		{
			name:    "read only holds only reader",
			email:   "reader@canonical.com",
			roleID:  db.RoleReadOnly,
			granted: []string{authorization.RelationReader},
		},
	}

	repo, database := mustInitAuthz(t)
	for _, tt := range tests {
		mustCreateUser(t, database, tt.email, tt.roleID)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, relation := range allRelations {
				want := slices.Contains(tt.granted, relation)
				got, err := repo.Check(authorization.SystemObject, relation, authorization.UserID(tt.email))
				if err != nil {
					t.Fatalf("Check(%s) returned an error: %s", relation, err)
				}
				if got != want {
					t.Errorf("Check(%s) = %t, want %t", relation, got, want)
				}
			}
		})
	}
}

// TestListObjectsResolvesTheFullRoleHierarchy is the reverse-lookup counterpart
// of TestCheckResolvesTheFullRoleHierarchy: it exercises ReadStartingWithUser
// rather than ReadUserTuple.
func TestListObjectsResolvesTheFullRoleHierarchy(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		roleID  db.RoleID
		granted []string
	}{
		{
			name:   "admin",
			email:  "admin@canonical.com",
			roleID: db.RoleAdmin,
			granted: []string{
				authorization.RelationAdmin,
				authorization.RelationCertificateManager,
				authorization.RelationCertificateRequestor,
				authorization.RelationReader,
			},
		},
		{
			name:   "certificate manager",
			email:  "manager@canonical.com",
			roleID: db.RoleCertificateManager,
			granted: []string{
				authorization.RelationCertificateManager,
				authorization.RelationCertificateRequestor,
				authorization.RelationReader,
			},
		},
		{
			name:    "certificate requestor",
			email:   "requestor@canonical.com",
			roleID:  db.RoleCertificateRequestor,
			granted: []string{authorization.RelationCertificateRequestor},
		},
		{
			name:    "read only",
			email:   "reader@canonical.com",
			roleID:  db.RoleReadOnly,
			granted: []string{authorization.RelationReader},
		},
	}

	repo, database := mustInitAuthz(t)
	for _, tt := range tests {
		mustCreateUser(t, database, tt.email, tt.roleID)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, relation := range allRelations {
				objects, err := repo.ListObjects("system", relation, authorization.UserID(tt.email))
				if err != nil {
					t.Fatalf("ListObjects(%s) returned an error: %s", relation, err)
				}
				if slices.Contains(tt.granted, relation) {
					if !slices.Contains(objects, authorization.SystemObject) {
						t.Errorf("ListObjects(%s) = %v, want it to contain %q", relation, objects, authorization.SystemObject)
					}
					continue
				}
				if len(objects) != 0 {
					t.Errorf("ListObjects(%s) = %v, want no objects", relation, objects)
				}
			}
		})
	}
}

// TestChecksFollowRoleChangesWithoutATupleWrite is the behavior the old
// dual-write path got wrong: UpdateUserRole never touched the tuple store, so a
// demoted admin kept admin permissions. Deriving tuples from role_id makes the
// role change take effect immediately, with no separate write to keep in sync.
func TestChecksFollowRoleChangesWithoutATupleWrite(t *testing.T) {
	const email = "demoted@canonical.com"

	repo, database := mustInitAuthz(t)
	userID := mustCreateUser(t, database, email, db.RoleAdmin)

	allowed, err := repo.Check(authorization.SystemObject, authorization.RelationAdmin, authorization.UserID(email))
	if err != nil {
		t.Fatalf("Check returned an error: %s", err)
	}
	if !allowed {
		t.Fatal("a newly created admin should pass an admin check")
	}

	if err := database.UpdateUserRole(db.ByUserID(userID), db.RoleReadOnly); err != nil {
		t.Fatalf("failed to update the user's role: %s", err)
	}

	allowed, err = repo.Check(authorization.SystemObject, authorization.RelationAdmin, authorization.UserID(email))
	if err != nil {
		t.Fatalf("Check returned an error: %s", err)
	}
	if allowed {
		t.Error("a demoted admin should no longer pass an admin check")
	}

	allowed, err = repo.Check(authorization.SystemObject, authorization.RelationReader, authorization.UserID(email))
	if err != nil {
		t.Fatalf("Check returned an error: %s", err)
	}
	if !allowed {
		t.Error("a user demoted to read only should still pass a reader check")
	}
}

// TestChecksFailClosedForUnknownPrincipals covers the inputs that reach the
// datastore when authorization is asked about something that does not exist.
func TestChecksFailClosedForUnknownPrincipals(t *testing.T) {
	repo, database := mustInitAuthz(t)
	mustCreateUser(t, database, "admin@canonical.com", db.RoleAdmin)

	tests := []struct {
		name     string
		object   string
		relation string
		user     string
	}{
		{
			name:     "unknown user",
			object:   authorization.SystemObject,
			relation: authorization.RelationReader,
			user:     authorization.UserID("nobody@canonical.com"),
		},
		{
			name:     "deleted user",
			object:   authorization.SystemObject,
			relation: authorization.RelationAdmin,
			user:     authorization.UserID("deleted@canonical.com"),
		},
		{
			name:     "unknown object of a known type",
			object:   "system:other",
			relation: authorization.RelationReader,
			user:     authorization.UserID("admin@canonical.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := repo.Check(tt.object, tt.relation, tt.user)
			if err != nil {
				t.Fatalf("Check returned an error: %s", err)
			}
			if allowed {
				t.Error("Check = true, want false")
			}
		})
	}
}

// TestDeletedUsersLoseAccess confirms that access is revoked by the user
// deletion itself, with no accompanying tuple delete.
func TestDeletedUsersLoseAccess(t *testing.T) {
	const email = "temporary@canonical.com"

	repo, database := mustInitAuthz(t)
	userID := mustCreateUser(t, database, email, db.RoleCertificateManager)

	if err := database.DeleteUser(db.ByUserID(userID)); err != nil {
		t.Fatalf("failed to delete the user: %s", err)
	}

	for _, relation := range allRelations {
		allowed, err := repo.Check(authorization.SystemObject, relation, authorization.UserID(email))
		if err != nil {
			t.Fatalf("Check(%s) returned an error: %s", relation, err)
		}
		if allowed {
			t.Errorf("Check(%s) = true for a deleted user, want false", relation)
		}
	}
}
