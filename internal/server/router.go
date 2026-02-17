package server

import (
	"net/http"

	"github.com/canonical/notary/internal/backends/observability/metrics"
	"go.uber.org/zap"
)

// NewRouter takes in a config struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewRouter(config *HandlerDependencies) http.Handler {
	apiV1Router := http.NewServeMux()
	apiV1Router.HandleFunc("GET /certificate_requests", requirePermission([]string{PermListCertificateRequests, PermListMyCertificateRequests}, config.Database.JWTSecret, config.AuthnRepository, ListCertificateRequests(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests", requirePermission([]string{PermCreateCertificateRequest}, config.Database.JWTSecret, config.AuthnRepository, CreateCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", requirePermission([]string{PermReadCertificateRequest, PermReadMyCertificateRequest}, config.Database.JWTSecret, config.AuthnRepository, GetCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", requirePermission([]string{PermDeleteCertificateRequest}, config.Database.JWTSecret, config.AuthnRepository, DeleteCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/reject", requirePermission([]string{PermRejectCertificateRequest}, config.Database.JWTSecret, config.AuthnRepository, RejectCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/sign", requirePermission([]string{PermSignCertificateRequest}, config.Database.JWTSecret, config.AuthnRepository, SignCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", requirePermission([]string{PermCreateCertificateRequestCertificate}, config.Database.JWTSecret, config.AuthnRepository, PostCertificateRequestCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", requirePermission([]string{PermDeleteCertificateRequestCertificate}, config.Database.JWTSecret, config.AuthnRepository, DeleteCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/revoke", requirePermission([]string{PermRevokeCertificateRequestCertificate}, config.Database.JWTSecret, config.AuthnRepository, RevokeCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /certificate_authorities", requirePermission([]string{PermListCertificateAuthorities}, config.Database.JWTSecret, config.AuthnRepository, ListCertificateAuthorities(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities", requirePermission([]string{PermCreateCertificateAuthority}, config.Database.JWTSecret, config.AuthnRepository, CreateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}", requirePermission([]string{PermReadCertificateAuthority}, config.Database.JWTSecret, config.AuthnRepository, GetCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("PUT /certificate_authorities/{id}", requirePermission([]string{PermUpdateCertificateAuthority}, config.Database.JWTSecret, config.AuthnRepository, UpdateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_authorities/{id}", requirePermission([]string{PermDeleteCertificateAuthority}, config.Database.JWTSecret, config.AuthnRepository, DeleteCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/sign", requirePermission([]string{PermSignCertificateAuthorityCertificate}, config.Database.JWTSecret, config.AuthnRepository, SignCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/certificate", requirePermission([]string{PermCreateCertificateAuthorityCertificate}, config.Database.JWTSecret, config.AuthnRepository, PostCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}/crl", GetCertificateAuthorityCRL(config))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/revoke", requirePermission([]string{PermRevokeCertificateAuthorityCertificate}, config.Database.JWTSecret, config.AuthnRepository, RevokeCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /accounts", requirePermission([]string{PermListUsers}, config.Database.JWTSecret, config.AuthnRepository, ListAccounts(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts", requirePermission([]string{PermCreateUser}, config.Database.JWTSecret, config.AuthnRepository, CreateAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /accounts/{id}", requirePermission([]string{PermReadUser}, config.Database.JWTSecret, config.AuthnRepository, GetAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /accounts/me", requirePermission([]string{PermReadMyUser}, config.Database.JWTSecret, config.AuthnRepository, GetMyAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", requirePermission([]string{PermDeleteUser}, config.Database.JWTSecret, config.AuthnRepository, DeleteAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", requirePermission([]string{PermUpdateUserPassword}, config.Database.JWTSecret, config.AuthnRepository, ChangeAccountPassword(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/me/change_password", requirePermission([]string{PermUpdateMyPassword}, config.Database.JWTSecret, config.AuthnRepository, ChangeMyPassword(config), config.SystemLogger, config.AuditLogger))

	if config.AuthnRepository != nil {
		apiV1Router.HandleFunc("GET /oauth/login", LoginOIDC(config))
		apiV1Router.HandleFunc("GET /oauth/callback", CallbackOIDC(config))
	}

	apiV1Router.HandleFunc("GET /config", requirePermission([]string{PermReadConfig}, config.Database.JWTSecret, config.AuthnRepository, GetConfigContent(config), config.SystemLogger, config.AuditLogger))

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
