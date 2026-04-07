package server

import (
	"net/http"

	"github.com/canonical/notary/internal/backends/observability/metrics"
	"go.uber.org/zap"
)

// allRoles is a convenience slice for endpoints accessible by every authenticated user.
var allRoles = []string{
	RoleNameAdmin,
	RoleNameCertificateManager,
	RoleNameCertificateRequestor,
	RoleNameReader,
}

// managerRoles covers admins and certificate managers.
var managerRoles = []string{
	RoleNameAdmin,
	RoleNameCertificateManager,
}

// requestorRoles covers admins, certificate managers, and certificate requestors.
var requestorRoles = []string{
	RoleNameAdmin,
	RoleNameCertificateManager,
	RoleNameCertificateRequestor,
}

// readerRoles covers admins, certificate managers, and readers (but NOT certificate requestors).
var readerRoles = []string{
	RoleNameAdmin,
	RoleNameCertificateManager,
	RoleNameReader,
}

// adminOnly restricts access to admins exclusively.
var adminOnly = []string{RoleNameAdmin}

// NewRouter takes in a config struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewRouter(config *HandlerDependencies) http.Handler {
	apiV1Router := http.NewServeMux()

	// Certificate request endpoints
	apiV1Router.HandleFunc("GET /certificate_requests", requirePermission(allRoles, config, ListCertificateRequests(config)))
	apiV1Router.HandleFunc("POST /certificate_requests", requirePermission(requestorRoles, config, CreateCertificateRequest(config)))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", requirePermission(allRoles, config, GetCertificateRequest(config)))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", requirePermission(managerRoles, config, DeleteCertificateRequest(config)))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/reject", requirePermission(managerRoles, config, RejectCertificateRequest(config)))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/sign", requirePermission(managerRoles, config, SignCertificateRequest(config)))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", requirePermission(managerRoles, config, PostCertificateRequestCertificate(config)))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", requirePermission(managerRoles, config, DeleteCertificate(config)))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/revoke", requirePermission(managerRoles, config, RevokeCertificate(config)))

	// Certificate authority endpoints
	apiV1Router.HandleFunc("GET /certificate_authorities", requirePermission(readerRoles, config, ListCertificateAuthorities(config)))
	apiV1Router.HandleFunc("POST /certificate_authorities", requirePermission(managerRoles, config, CreateCertificateAuthority(config)))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}", requirePermission(readerRoles, config, GetCertificateAuthority(config)))
	apiV1Router.HandleFunc("PUT /certificate_authorities/{id}", requirePermission(managerRoles, config, UpdateCertificateAuthority(config)))
	apiV1Router.HandleFunc("DELETE /certificate_authorities/{id}", requirePermission(managerRoles, config, DeleteCertificateAuthority(config)))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/sign", requirePermission(managerRoles, config, SignCertificateAuthority(config)))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/certificate", requirePermission(managerRoles, config, PostCertificateAuthorityCertificate(config)))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}/crl", GetCertificateAuthorityCRL(config))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/revoke", requirePermission(managerRoles, config, RevokeCertificateAuthorityCertificate(config)))

	// Account endpoints
	apiV1Router.HandleFunc("GET /accounts", requirePermission(adminOnly, config, ListAccounts(config)))
	apiV1Router.HandleFunc("POST /accounts", firstUserOrAdmin(config, CreateAccount(config)))
	apiV1Router.HandleFunc("GET /accounts/{id}", requirePermission(adminOnly, config, GetAccount(config)))
	apiV1Router.HandleFunc("GET /accounts/me", requirePermission(allRoles, config, GetMyAccount(config)))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", requirePermission(adminOnly, config, DeleteAccount(config)))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", requirePermission(adminOnly, config, ChangeAccountPassword(config)))
	apiV1Router.HandleFunc("POST /accounts/me/change_password", requirePermission(allRoles, config, ChangeMyPassword(config)))

	if config.AuthnRepository != nil {
		apiV1Router.HandleFunc("GET /oauth/login", LoginOIDC(config))
		apiV1Router.HandleFunc("GET /oauth/callback", CallbackOIDC(config))
	}

	apiV1Router.HandleFunc("GET /config", requirePermission(allRoles, config, GetConfigContent(config)))

	m := metrics.NewMetricsSubsystem(config.Database, config.SystemLogger)
	frontendHandler, err := newFrontendFileServer()
	if err != nil {
		config.SystemLogger.Fatal("Failed to create frontend file server", zap.Error(err))
	}
	ctx := middlewareContext{
		jwtSecret:    config.Database.JWTSecret,
		systemLogger: config.SystemLogger,
		auditLogger:  config.AuditLogger,
		tracer:       config.TracingRepository,
	}
	apiMiddlewareStack := createMiddlewareStack(
		limitRequestSize(MAX_KILOBYTES, config.SystemLogger),
		metricsMiddleware(m),
		auditLoggingMiddleware(&ctx),
		loggingMiddleware(&ctx),
		tracingMiddleware(&ctx),
	)
	metricsMiddlewareStack := createMiddlewareStack(
		metricsMiddleware(m),
		tracingMiddleware(&ctx),
	)

	router := http.NewServeMux()
	router.HandleFunc("POST /login", Login(config))
	router.HandleFunc("POST /logout", Logout(config))
	router.HandleFunc("GET /status", GetStatus(config))
	router.Handle("/metrics", m.Handler)
	router.Handle("/api/v1/", http.StripPrefix("/api/v1", apiMiddlewareStack(apiV1Router)))
	router.Handle("/", metricsMiddlewareStack(frontendHandler))

	return router
}
