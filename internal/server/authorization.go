package server

const (
	// User permissions
	PermListUsers          = "user:list"
	PermCreateUser         = "user:create"
	PermUpdateUser         = "user:update"
	PermUpdateUserPassword = "user:update_password"
	PermUpdateMyPassword   = "user:update_my_password"
	PermReadUser           = "user:read"
	PermReadMyUser         = "user:read_my_user"
	PermDeleteUser         = "user:delete"

	// Config permissions
	PermReadConfig = "config:read"

	// Certificate request permissions
	PermListCertificateRequests             = "certificate_request:list"
	PermListMyCertificateRequests           = "certificate_request:list_my"
	PermCreateCertificateRequest            = "certificate_request:create"
	PermReadCertificateRequest              = "certificate_request:read"
	PermReadMyCertificateRequest            = "certificate_request:read_my"
	PermDeleteCertificateRequest            = "certificate_request:delete"
	PermRejectCertificateRequest            = "certificate_request:reject"
	PermSignCertificateRequest              = "certificate_request:sign"
	PermCreateCertificateRequestCertificate = "certificate_request:certificate:create"
	PermDeleteCertificateRequestCertificate = "certificate_request:certificate:delete"
	PermRevokeCertificateRequestCertificate = "certificate_request:certificate:revoke"

	// Certificate authority permissions
	PermListCertificateAuthorities            = "certificate_authority:list"
	PermCreateCertificateAuthority            = "certificate_authority:create"
	PermReadCertificateAuthority              = "certificate_authority:read"
	PermUpdateCertificateAuthority            = "certificate_authority:update"
	PermDeleteCertificateAuthority            = "certificate_authority:delete"
	PermSignCertificateAuthorityCertificate   = "certificate_authority:sign"
	PermCreateCertificateAuthorityCertificate = "certificate_authority:certificate:create"
	PermRevokeCertificateAuthorityCertificate = "certificate_authority:certificate:revoke"

	// Backup permissions
	PermCreateBackup  = "backup:create"
	PermRestoreBackup = "backup:restore"
)

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

var PermissionsByRole = map[RoleID][]string{
	RoleAdmin: {
		PermListUsers,
		PermCreateUser,
		PermUpdateUser,
		PermUpdateUserPassword,
		PermUpdateMyPassword,
		PermReadUser,
		PermReadMyUser,
		PermDeleteUser,
		PermReadConfig,
		PermCreateBackup,
		PermRestoreBackup,
		PermListCertificateRequests,
		PermListMyCertificateRequests,
		PermCreateCertificateRequest,
		PermReadCertificateRequest,
		PermReadMyCertificateRequest,
		PermDeleteCertificateRequest,
		PermRejectCertificateRequest,
		PermSignCertificateRequest,
		PermCreateCertificateRequestCertificate,
		PermDeleteCertificateRequestCertificate,
		PermRevokeCertificateRequestCertificate,
		PermListCertificateAuthorities,
		PermCreateCertificateAuthority,
		PermReadCertificateAuthority,
		PermUpdateCertificateAuthority,
		PermDeleteCertificateAuthority,
		PermSignCertificateAuthorityCertificate,
		PermCreateCertificateAuthorityCertificate,
		PermRevokeCertificateAuthorityCertificate,
	},

	RoleCertificateManager: {
		PermReadMyUser,
		PermReadConfig,
		PermUpdateMyPassword,
		PermListCertificateRequests,
		PermCreateCertificateRequest,
		PermReadCertificateRequest,
		PermDeleteCertificateRequest,
		PermRejectCertificateRequest,
		PermSignCertificateRequest,
		PermCreateCertificateRequestCertificate,
		PermDeleteCertificateRequestCertificate,
		PermRevokeCertificateRequestCertificate,
		PermListCertificateAuthorities,
		PermCreateCertificateAuthority,
		PermReadCertificateAuthority,
		PermUpdateCertificateAuthority,
		PermDeleteCertificateAuthority,
		PermSignCertificateAuthorityCertificate,
		PermCreateCertificateAuthorityCertificate,
		PermRevokeCertificateAuthorityCertificate,
	},

	RoleCertificateRequestor: {
		PermReadMyUser,
		PermUpdateMyPassword,
		PermCreateCertificateRequest,
		PermReadMyCertificateRequest,
		PermListMyCertificateRequests,
	},

	RoleReadOnly: {
		PermReadMyUser,
		PermUpdateMyPassword,
		PermListCertificateRequests,
		PermReadCertificateRequest,
		PermListCertificateAuthorities,
		PermReadCertificateAuthority,
		PermReadConfig,
	},
}

func getPermissionsFromRoleID(roleID RoleID) []string {
	if roleID.IsValid() {
		return PermissionsByRole[roleID]
	}
	return nil
}
