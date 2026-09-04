package authorization

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

const SystemObject = "system:notary"

const userPrincipalPrefix = "user:"

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

// UserID formats a principal from the users table primary key (e.g. "user:12").
// Returns "" if id is not a valid user id, so callers that check with an empty
// principal fail closed.
func UserID(id int64) string {
	if id <= 0 {
		return ""
	}
	return fmt.Sprintf("%s%d", userPrincipalPrefix, id)
}

// Check returns whether user has relation on object.
// Only SystemObject is authorized today; other objects are denied.
func (r *AuthzRepository) Check(object, relation, user string) (bool, error) {
	return r.CheckAny(object, user, relation)
}

// CheckAny returns whether user has any of the given relations on object.
// The account is loaded once. A missing repository is treated as deny for
// Check compatibility; CertificateRequestorOnly still requires a repository.
func (r *AuthzRepository) CheckAny(object, user string, relations ...string) (bool, error) {
	if r == nil || r.database == nil || object != SystemObject || user == "" || len(relations) == 0 {
		return false, nil
	}
	account, err := r.userByPrincipal(user)
	if err != nil {
		return false, err
	}
	if account == nil {
		return false, nil
	}
	for _, relation := range relations {
		if roleHasRelation(account.RoleID, relation) {
			return true, nil
		}
	}
	return false, nil
}

// CertificateRequestorOnly is true when the user may create CSRs but not manage
// others': they have certificate_requestor and not certificate_manager.
// user is a principal from UserID.
func (r *AuthzRepository) CertificateRequestorOnly(user string) (bool, error) {
	if r == nil || r.database == nil {
		return false, errors.New("authorization repository is not configured")
	}
	account, err := r.userByPrincipal(user)
	if err != nil {
		return false, err
	}
	if account == nil {
		return false, nil
	}
	if roleHasRelation(account.RoleID, RelationCertificateManager) {
		return false, nil
	}
	return roleHasRelation(account.RoleID, RelationCertificateRequestor), nil
}

func (r *AuthzRepository) userByPrincipal(user string) (*db.User, error) {
	id, ok := idFromUserPrincipal(user)
	if !ok {
		return nil, nil
	}
	account, err := r.database.GetUser(db.ByUserID(id))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return account, nil
}

func idFromUserPrincipal(user string) (int64, bool) {
	if !strings.HasPrefix(user, userPrincipalPrefix) {
		return 0, false
	}
	raw := strings.TrimPrefix(user, userPrincipalPrefix)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
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
