package server

import "github.com/canonical/notary/internal/db"

// Role name constants used in OpenFGA tuples and checks against "system:notary".
const (
	RoleNameAdmin                = "admin"
	RoleNameCertificateManager   = "certificate_manager"
	RoleNameCertificateRequestor = "certificate_requestor"
	RoleNameReader               = "reader"
)

// RoleID mirrors db.RoleID for use within the server package.
type RoleID int

const (
	RoleAdmin                RoleID = 0
	RoleCertificateManager   RoleID = 1
	RoleCertificateRequestor RoleID = 2
	RoleReadOnly             RoleID = 3
)

func (r RoleID) IsValid() bool {
	switch r {
	case RoleAdmin, RoleCertificateManager, RoleCertificateRequestor, RoleReadOnly:
		return true
	default:
		return false
	}
}

// RoleIDToRelation maps a db.RoleID to the corresponding OpenFGA relation name on "system:notary".
func RoleIDToRelation(roleID db.RoleID) string {
	switch roleID {
	case db.RoleAdmin:
		return RoleNameAdmin
	case db.RoleCertificateManager:
		return RoleNameCertificateManager
	case db.RoleCertificateRequestor:
		return RoleNameCertificateRequestor
	default:
		return RoleNameReader
	}
}
