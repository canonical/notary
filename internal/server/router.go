package server

import (
	"net/http"

	"github.com/canonical/notary/internal/metrics"
	"go.uber.org/zap"
)

// NewRouter takes in a config struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewRouter(config *HandlerConfig) http.Handler {
	apiV1Router := http.NewServeMux()
	apiV1Router.HandleFunc("GET /certificate_requests", requirePermission(PermListCertificateRequests, config.JWTSecret, ListCertificateRequests(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests", requirePermission(PermCreateCertificateRequest, config.JWTSecret, CreateCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", requirePermission(PermReadCertificateRequest, config.JWTSecret, GetCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", requirePermission(PermDeleteCertificateRequest, config.JWTSecret, DeleteCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/reject", requirePermission(PermRejectCertificateRequest, config.JWTSecret, RejectCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/sign", requirePermission(PermSignCertificateRequest, config.JWTSecret, SignCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", requirePermission(PermCreateCertificateRequestCertificate, config.JWTSecret, PostCertificateRequestCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", requirePermission(PermDeleteCertificateRequestCertificate, config.JWTSecret, DeleteCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/revoke", requirePermission(PermRevokeCertificateRequestCertificate, config.JWTSecret, RevokeCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /certificate_authorities", requirePermission(PermListCertificateAuthorities, config.JWTSecret, ListCertificateAuthorities(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities", requirePermission(PermCreateCertificateAuthority, config.JWTSecret, CreateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}", requirePermission(PermReadCertificateAuthority, config.JWTSecret, GetCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("PUT /certificate_authorities/{id}", requirePermission(PermUpdateCertificateAuthority, config.JWTSecret, UpdateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_authorities/{id}", requirePermission(PermDeleteCertificateAuthority, config.JWTSecret, DeleteCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/sign", requirePermission(PermSignCertificateAuthorityCertificate, config.JWTSecret, SignCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/certificate", requirePermission(PermCreateCertificateAuthorityCertificate, config.JWTSecret, PostCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}/crl", GetCertificateAuthorityCRL(config))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/revoke", requirePermission(PermRevokeCertificateAuthorityCertificate, config.JWTSecret, RevokeCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /accounts", requirePermission(PermListUsers, config.JWTSecret, ListAccounts(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts", requirePermissionOrFirstUser(PermCreateUser, config.JWTSecret, config.DB, CreateAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /accounts/{id}", requirePermission(PermReadUser, config.JWTSecret, GetAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", requirePermission(PermDeleteUser, config.JWTSecret, DeleteAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", requirePermission(PermUpdateUserPassword, config.JWTSecret, ChangeAccountPassword(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/me/change_password", requirePermission(PermUpdateMyPassword, config.JWTSecret, ChangeMyPassword(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /config", requirePermission(PermReadConfig, config.JWTSecret, GetConfigContent(config), config.SystemLogger, config.AuditLogger))

	m := metrics.NewMetricsSubsystem(config.DB, config.SystemLogger)
	frontendHandler, err := newFrontendFileServer()
	if err != nil {
		config.SystemLogger.Fatal("Failed to create frontend file server", zap.Error(err))
	}
	ctx := middlewareContext{
		jwtSecret:    config.JWTSecret,
		systemLogger: config.SystemLogger,
		auditLogger:  config.AuditLogger,
	}
	apiMiddlewareStack := createMiddlewareStack(
		limitRequestSize(MAX_KILOBYTES, config.SystemLogger),
		metricsMiddleware(m),
		auditLoggingMiddleware(&ctx),
		loggingMiddleware(&ctx),
	)
	metricsMiddlewareStack := createMiddlewareStack(
		metricsMiddleware(m),
	)

	router := http.NewServeMux()
	router.HandleFunc("POST /login", Login(config))
	router.HandleFunc("GET /status", GetStatus(config))
	router.Handle("/metrics", m.Handler)
	router.Handle("/api/v1/", http.StripPrefix("/api/v1", apiMiddlewareStack(apiV1Router)))
	router.Handle("/", metricsMiddlewareStack(frontendHandler))

	return router
}
