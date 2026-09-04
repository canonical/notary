package server

import (
	"github.com/canonical/notary/internal/backends/authorization"
)

// Role name constants used in permission checks against system:notary.
const (
	RoleNameAdmin                = authorization.RelationAdmin
	RoleNameCertificateManager   = authorization.RelationCertificateManager
	RoleNameCertificateRequestor = authorization.RelationCertificateRequestor
	RoleNameReader               = authorization.RelationReader
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
