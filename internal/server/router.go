package server

import (
	"net/http"

	"github.com/canonical/notary/internal/metrics"
	"go.uber.org/zap"
)

// NewHandler takes in a config struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewHandler(config *HandlerConfig) http.Handler {
	apiV1Router := http.NewServeMux()
	apiV1Router.HandleFunc("GET /certificate_requests", adminOrUser(config.JWTSecret, ListCertificateRequests(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_requests", adminOrUser(config.JWTSecret, CreateCertificateRequest(config), config.Logger))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", adminOrUser(config.JWTSecret, GetCertificateRequest(config), config.Logger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", adminOrUser(config.JWTSecret, DeleteCertificateRequest(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/reject", adminOrUser(config.JWTSecret, RejectCertificateRequest(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/sign", adminOrUser(config.JWTSecret, SignCertificateRequest(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", adminOrUser(config.JWTSecret, PostCertificateRequestCertificate(config), config.Logger))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", adminOrUser(config.JWTSecret, DeleteCertificate(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/revoke", adminOrUser(config.JWTSecret, RevokeCertificate(config), config.Logger))

	apiV1Router.HandleFunc("GET /certificate_authorities", adminOnly(config.JWTSecret, ListCertificateAuthorities(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_authorities", adminOnly(config.JWTSecret, CreateCertificateAuthority(config), config.Logger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}", adminOnly(config.JWTSecret, GetCertificateAuthority(config), config.Logger))
	apiV1Router.HandleFunc("PUT /certificate_authorities/{id}", adminOnly(config.JWTSecret, UpdateCertificateAuthority(config), config.Logger))
	apiV1Router.HandleFunc("DELETE /certificate_authorities/{id}", adminOnly(config.JWTSecret, DeleteCertificateAuthority(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/sign", adminOnly(config.JWTSecret, SignCertificateAuthority(config), config.Logger))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/certificate", adminOnly(config.JWTSecret, PostCertificateAuthorityCertificate(config), config.Logger))
	apiV1Router.HandleFunc("GET /certificate_authorities/{id}/crl", GetCertificateAuthorityCRL(config))
	apiV1Router.HandleFunc("POST /certificate_authorities/{id}/revoke", adminOnly(config.JWTSecret, RevokeCertificateAuthorityCertificate(config), config.Logger))

	apiV1Router.HandleFunc("GET /accounts", adminOnly(config.JWTSecret, ListAccounts(config), config.Logger))
	apiV1Router.HandleFunc("POST /accounts", adminOrFirstUser(config.JWTSecret, config.DB, CreateAccount(config), config.Logger))
	apiV1Router.HandleFunc("GET /accounts/{id}", adminOrMe(config.JWTSecret, GetAccount(config), config.Logger))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", adminOnly(config.JWTSecret, DeleteAccount(config), config.Logger))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", adminOrMe(config.JWTSecret, ChangeAccountPassword(config), config.Logger))

	apiV1Router.HandleFunc("GET /config", adminOrUser(config.JWTSecret, GetConfigContent(config), config.Logger))

	m := metrics.NewMetricsSubsystem(config.DB, config.Logger)
	frontendHandler, err := newFrontendFileServer()
	if err != nil {
		config.Logger.Fatal("Failed to create frontend file server", zap.Error(err))
	}
	ctx := middlewareContext{
		jwtSecret: config.JWTSecret,
		logger:    config.Logger,
	}
	apiMiddlewareStack := createMiddlewareStack(
		limitRequestSize(MAX_KILOBYTES, config.Logger),
		metricsMiddleware(m),
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
