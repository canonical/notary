package server

import (
	"net/http"

	"github.com/canonical/notary/internal/metrics"
)

// NewHandler takes in an environment struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewHandler(env *HandlerConfig) http.Handler {
	apiV1Router := http.NewServeMux()
	apiV1Router.HandleFunc("GET /certificate_requests", GetCertificateRequests(env))
	apiV1Router.HandleFunc("POST /certificate_requests", PostCertificateRequest(env))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", GetCertificateRequest(env))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", DeleteCertificateRequest(env))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", PostCertificate(env))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/reject", RejectCertificate(env))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", DeleteCertificate(env))

	apiV1Router.HandleFunc("GET /accounts", GetUserAccounts(env))
	apiV1Router.HandleFunc("POST /accounts", PostUserAccount(env))
	apiV1Router.HandleFunc("GET /accounts/{id}", GetUserAccount(env))
	apiV1Router.HandleFunc("DELETE /accounts/{id}", DeleteUserAccount(env))
	apiV1Router.HandleFunc("POST /accounts/{id}/change_password", ChangeUserAccountPassword(env))

	m := metrics.NewMetricsSubsystem(env.DB)
	frontendHandler := newFrontendFileServer()

	router := http.NewServeMux()
	router.HandleFunc("POST /login", Login(env))
	router.HandleFunc("/status", HealthCheck(env))
	router.Handle("/metrics", m.Handler)
	router.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1Router))
	router.Handle("/", frontendHandler)

	ctx := middlewareContext{
		metrics:            m,
		jwtSecret:          env.JWTSecret,
		firstAccountIssued: false,
	}
	middleware := createMiddlewareStack(
		authMiddleware(&ctx),
		metricsMiddleware(&ctx),
		loggingMiddleware(&ctx),
	)
	return middleware(router)
}
