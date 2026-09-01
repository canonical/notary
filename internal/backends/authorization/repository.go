package authorization

import (
	"errors"
	"fmt"
	"strings"

	"github.com/canonical/notary/internal/db"
)

const SystemObject = "system:notary"

// Role names used in Check against SystemObject. Inheritance matches the
// previous authorization model: admin implies certificate_manager; manager
// implies certificate_requestor and reader. certificate_requestor does not
// imply reader.
const (
	RelationAdmin                = "admin"
	RelationCertificateManager   = "certificate_manager"
	RelationCertificateRequestor = "certificate_requestor"
	RelationReader               = "reader"
)

// AuthzRepository answers authorization checks from users.role_id in dqlite.
// Handlers should go through Check rather than reading role_id themselves so a
// future ReBAC backend can replace this implementation.
type AuthzRepository struct {
	database *db.DatabaseRepository
}

func New(database *db.DatabaseRepository) *AuthzRepository {
	return &AuthzRepository{database: database}
}

// UserID formats a user ID (e.g. "user:admin@notary.local").
// Returns "" if email is empty, so callers that check authorization with an
// empty userID fail the check (resulting in a 403).
func UserID(email string) string {
	if email == "" {
		return ""
	}
	return fmt.Sprintf("user:%s", email)
}

// Check returns whether user has relation on object.
// Only SystemObject is authorized today; other objects are denied.
func (r *AuthzRepository) Check(object, relation, user string) (bool, error) {
	if r == nil || r.database == nil || object != SystemObject || user == "" {
		return false, nil
	}
	email, ok := emailFromUserID(user)
	if !ok {
		return false, nil
	}
	account, err := r.database.GetUser(db.ByEmail(email))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return roleHasRelation(account.RoleID, relation), nil
}

// CertificateRequestorOnly is true when the user may create CSRs but not manage
// others': they have certificate_requestor and not certificate_manager.
func (r *AuthzRepository) CertificateRequestorOnly(email string) (bool, error) {
	if r == nil || r.database == nil {
		return false, errors.New("authorization repository is not configured")
	}
	userID := UserID(email)
	manager, err := r.Check(SystemObject, RelationCertificateManager, userID)
	if err != nil {
		return false, err
	}
	if manager {
		return false, nil
	}
	return r.Check(SystemObject, RelationCertificateRequestor, userID)
}

func emailFromUserID(user string) (string, bool) {
	const prefix = "user:"
	if !strings.HasPrefix(user, prefix) {
		return "", false
	}
	email := strings.TrimPrefix(user, prefix)
	if email == "" {
		return "", false
	}
	return email, true
}

func roleHasRelation(roleID db.RoleID, relation string) bool {
	switch relation {
	case RelationAdmin:
		return roleID == db.RoleAdmin
	case RelationCertificateManager:
		return roleID == db.RoleAdmin || roleID == db.RoleCertificateManager
	case RelationCertificateRequestor:
		return roleID == db.RoleAdmin || roleID == db.RoleCertificateManager || roleID == db.RoleCertificateRequestor
	case RelationReader:
		return roleID == db.RoleAdmin || roleID == db.RoleCertificateManager || roleID == db.RoleReadOnly
	default:
		return false
	}
}
