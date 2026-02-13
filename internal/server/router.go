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
	apiV1Router.HandleFunc("GET /certificate_requests", requirePermission([]string{PermListCertificateRequests, PermListMyCertificateRequests}, config.JWTSecret, config.OIDCConfig, ListCertificateRequests(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests", requirePermission([]string{PermCreateCertificateRequest}, config.JWTSecret, config.OIDCConfig, CreateCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", requirePermission([]string{PermReadCertificateRequest, PermReadMyCertificateRequest}, config.JWTSecret, config.OIDCConfig, GetCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", requirePermission([]string{PermDeleteCertificateRequest}, config.JWTSecret, config.OIDCConfig, DeleteCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/reject", requirePermission([]string{PermRejectCertificateRequest}, config.JWTSecret, config.OIDCConfig, RejectCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/sign", requirePermission([]string{PermSignCertificateRequest}, config.JWTSecret, config.OIDCConfig, SignCertificateRequest(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", requirePermission([]string{PermCreateCertificateRequestCertificate}, config.JWTSecret, config.OIDCConfig, PostCertificateRequestCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", requirePermission([]string{PermDeleteCertificateRequestCertificate}, config.JWTSecret, config.OIDCConfig, DeleteCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/revoke", requirePermission([]string{PermRevokeCertificateRequestCertificate}, config.JWTSecret, config.OIDCConfig, RevokeCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /certificate_authorities", requirePermission([]string{PermListCertificateAuthorities}, config.JWTSecret, config.OIDCConfig, ListCertificateAuthorities(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities", requirePermission([]string{PermCreateCertificateAuthority}, config.JWTSecret, config.OIDCConfig, CreateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}", requirePermission([]string{PermReadCertificateAuthority}, config.JWTSecret, config.OIDCConfig, GetCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("PUT /certificate_authorities/{id}", requirePermission([]string{PermUpdateCertificateAuthority}, config.JWTSecret, config.OIDCConfig, UpdateCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /certificate_authorities/{id}", requirePermission([]string{PermDeleteCertificateAuthority}, config.JWTSecret, config.OIDCConfig, DeleteCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/sign", requirePermission([]string{PermSignCertificateAuthorityCertificate}, config.JWTSecret, config.OIDCConfig, SignCertificateAuthority(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/certificate", requirePermission([]string{PermCreateCertificateAuthorityCertificate}, config.JWTSecret, config.OIDCConfig, PostCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}/crl", GetCertificateAuthorityCRL(config))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/revoke", requirePermission([]string{PermRevokeCertificateAuthorityCertificate}, config.JWTSecret, config.OIDCConfig, RevokeCertificateAuthorityCertificate(config), config.SystemLogger, config.AuditLogger))

	apiV1Router.HandleFunc("GET /accounts", requirePermission([]string{PermListUsers}, config.JWTSecret, config.OIDCConfig, ListAccounts(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts", requirePermissionOrFirstUser(PermCreateUser, config.JWTSecret, config.OIDCConfig, config.DB, CreateAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /accounts/{id}", requirePermission([]string{PermReadUser}, config.JWTSecret, config.OIDCConfig, GetAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("GET /accounts/me", requirePermission([]string{PermReadMyUser}, config.JWTSecret, config.OIDCConfig, GetMyAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", requirePermission([]string{PermDeleteUser}, config.JWTSecret, config.OIDCConfig, DeleteAccount(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", requirePermission([]string{PermUpdateUserPassword}, config.JWTSecret, config.OIDCConfig, ChangeAccountPassword(config), config.SystemLogger, config.AuditLogger))
	apiV1Router.HandleFunc("POST /accounts/me/change_password", requirePermission([]string{PermUpdateMyPassword}, config.JWTSecret, config.OIDCConfig, ChangeMyPassword(config), config.SystemLogger, config.AuditLogger))

	if config.OIDCConfig != nil {
		apiV1Router.HandleFunc("GET /oauth/login", LoginOIDC(config))
		apiV1Router.HandleFunc("GET /oauth/callback", CallbackOIDC(config))
	}

	apiV1Router.HandleFunc("GET /config", requirePermission([]string{PermReadConfig}, config.JWTSecret, config.OIDCConfig, GetConfigContent(config), config.SystemLogger, config.AuditLogger))

	m := metrics.NewMetricsSubsystem(config.DB, config.SystemLogger)
	frontendHandler, err := newFrontendFileServer()
	if err != nil {
		config.SystemLogger.Fatal("Failed to create frontend file server", zap.Error(err))
	}
	ctx := middlewareContext{
		jwtSecret:    config.JWTSecret,
		systemLogger: config.SystemLogger,
		auditLogger:  config.AuditLogger,
		tracer:       config.Tracer,
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
