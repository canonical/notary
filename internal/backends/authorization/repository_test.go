package authorization_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCheckRoleInheritance(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)

	users := []struct {
		email  string
		roleID db.RoleID
	}{
		{"admin@example.com", db.RoleAdmin},
		{"manager@example.com", db.RoleCertificateManager},
		{"requestor@example.com", db.RoleCertificateRequestor},
		{"reader@example.com", db.RoleReadOnly},
	}
	ids := map[string]int64{}
	for _, u := range users {
		id, err := database.CreateUser(u.email, "Password123!", u.roleID)
		if err != nil {
			t.Fatalf("create %s: %s", u.email, err)
		}
		ids[u.email] = id
	}

	cases := []struct {
		email    string
		relation string
		want     bool
	}{
		{"admin@example.com", authorization.RelationAdmin, true},
		{"admin@example.com", authorization.RelationCertificateManager, true},
		{"admin@example.com", authorization.RelationCertificateRequestor, true},
		{"admin@example.com", authorization.RelationReader, true},
		{"manager@example.com", authorization.RelationAdmin, false},
		{"manager@example.com", authorization.RelationCertificateManager, true},
		{"manager@example.com", authorization.RelationCertificateRequestor, true},
		{"manager@example.com", authorization.RelationReader, true},
		{"requestor@example.com", authorization.RelationAdmin, false},
		{"requestor@example.com", authorization.RelationCertificateManager, false},
		{"requestor@example.com", authorization.RelationCertificateRequestor, true},
		{"requestor@example.com", authorization.RelationReader, false},
		{"reader@example.com", authorization.RelationAdmin, false},
		{"reader@example.com", authorization.RelationCertificateManager, false},
		{"reader@example.com", authorization.RelationCertificateRequestor, false},
		{"reader@example.com", authorization.RelationReader, true},
	}
	for _, tc := range cases {
		got, err := authz.Check(authorization.SystemObject, tc.relation, authorization.UserID(ids[tc.email]))
		if err != nil {
			t.Fatalf("Check(%s, %s): %s", tc.email, tc.relation, err)
		}
		if got != tc.want {
			t.Errorf("Check(%s, %s) = %v, want %v", tc.email, tc.relation, got, tc.want)
		}
	}
}

func TestCheckDeniesUnknownUserAndObject(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)
	id, err := database.CreateUser("admin@example.com", "Password123!", db.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	got, err := authz.Check(authorization.SystemObject, authorization.RelationAdmin, authorization.UserID(id+999))
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("missing user should be denied")
	}

	got, err = authz.Check("certificate_authority:1", authorization.RelationAdmin, authorization.UserID(id))
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("non-system object should be denied")
	}

	got, err = authz.Check(authorization.SystemObject, authorization.RelationAdmin, "")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("empty user should be denied")
	}

	got, err = authz.Check(authorization.SystemObject, authorization.RelationAdmin, "user:admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("email principal should be denied")
	}
}

func TestCertificateRequestorOnly(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)
	users := []struct {
		email  string
		roleID db.RoleID
		want   bool
	}{
		{"admin@example.com", db.RoleAdmin, false},
		{"manager@example.com", db.RoleCertificateManager, false},
		{"requestor@example.com", db.RoleCertificateRequestor, true},
		{"reader@example.com", db.RoleReadOnly, false},
	}
	for _, u := range users {
		id, err := database.CreateUser(u.email, "Password123!", u.roleID)
		if err != nil {
			t.Fatalf("create %s: %s", u.email, err)
		}
		got, err := authz.CertificateRequestorOnly(authorization.UserID(id))
		if err != nil {
			t.Fatalf("%s: %s", u.email, err)
		}
		if got != u.want {
			t.Errorf("%s: got %v, want %v", u.email, got, u.want)
		}
	}
}

func TestCheckFollowsRoleUpdate(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)
	id, err := database.CreateUser("user@example.com", "Password123!", db.RoleReadOnly)
	if err != nil {
		t.Fatal(err)
	}

	got, err := authz.Check(authorization.SystemObject, authorization.RelationCertificateManager, authorization.UserID(id))
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("reader should not have certificate_manager")
	}

	if err := database.UpdateUserRole(db.ByUserID(id), db.RoleCertificateManager); err != nil {
		t.Fatal(err)
	}
	got, err = authz.Check(authorization.SystemObject, authorization.RelationCertificateManager, authorization.UserID(id))
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("role update should be visible to Check")
	}
}

func TestCheckOIDCUserWithoutEmail(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)
	user, err := database.CreateOIDCUser("", "idp|no-email", db.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	got, err := authz.Check(authorization.SystemObject, authorization.RelationAdmin, authorization.UserID(user.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("OIDC admin without email should authorize via user id")
	}
}

func TestCheckAnyMatchesFirstRelation(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	authz := authorization.New(database)
	id, err := database.CreateUser("reader@example.com", "Password123!", db.RoleReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	principal := authorization.UserID(id)
	got, err := authz.CheckAny(authorization.SystemObject, principal,
		authorization.RelationAdmin,
		authorization.RelationCertificateManager,
		authorization.RelationCertificateRequestor,
		authorization.RelationReader,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("reader should match CheckAny when reader is among allowed relations")
	}
	got, err = authz.CheckAny(authorization.SystemObject, principal,
		authorization.RelationAdmin,
		authorization.RelationCertificateManager,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("reader should not match admin or manager")
	}
}

func TestNewDoesNotCreateOpenFGASidecar(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	_ = authorization.New(database)
	path := filepath.Join(database.Path, "openfga.sqlite")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("authorization.New should not create %s: %v", path, err)
	}
}

func TestCertificateRequestorOnlyRequiresRepository(t *testing.T) {
	var authz *authorization.AuthzRepository
	_, err := authz.CertificateRequestorOnly(authorization.UserID(1))
	if err == nil {
		t.Fatal("expected error when authz repository is nil")
	}
}
