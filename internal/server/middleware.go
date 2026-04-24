package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/backends/observability/metrics"
	"github.com/canonical/notary/internal/backends/observability/tracing"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	MAX_KILOBYTES = 100
)

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	jwtSecret          []byte
	systemLogger       *zap.Logger
	auditLogger        *log.AuditLogger
	tracer             *tracing.TracingRepository
}

// createMiddlewareStack chains the given middleware functions to wrap the api.
// Each middleware functions calls next.ServeHTTP in order to resume the chain of execution.
// The order the middleware functions are given to createMiddlewareStack matters.
// Any code before next.ServeHTTP is called is executed in the given middleware's order.
// Any code after next.ServeHTTP is called is executed in the given middleware's reverse order.
func createMiddlewareStack(middleware ...middleware) middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middleware) - 1; i >= 0; i-- {
			mw := middleware[i]
			next = mw(next)
		}
		return next
	}
}

// limitRequestSize is a middleware that limits the size of the request body to maxKilobytes.
func limitRequestSize(maxKilobytes int64, logger *zap.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxKilobytes<<10)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				logger.Warn("request body exceeds maximum size", zap.Error(err), zap.Int64("max_kilobytes", maxKilobytes))
				writeResponse(w, http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge), nil, logger)
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

// The Metrics middleware captures any request relevant to a metric and records it for prometheus.
func metricsMiddleware(metrics *metrics.PrometheusMetrics) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := promhttp.InstrumentHandlerCounter(
				&metrics.RequestsTotal,
				promhttp.InstrumentHandlerDuration(
					&metrics.RequestsDuration,
					next,
				),
			)
			base.ServeHTTP(w, r)
		})
	}
}

// tracingMiddleware adds OpenTelemetry span creation and propagation to each request
func tracingMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/_next") || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}
			if ctx.tracer == nil {
				next.ServeHTTP(w, r)
				return
			}

			spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			spanCtx, span := ctx.tracer.Tracer.Start(
				r.Context(),
				spanName,
				trace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.url", r.URL.String()),
					attribute.String("http.host", r.Host),
					attribute.String("http.user_agent", r.UserAgent()),
				),
			)
			defer span.End()

			clonedWriter := newResponseWriter(w)
			r = r.WithContext(spanCtx)
			next.ServeHTTP(clonedWriter, r)
			span.SetAttributes(
				attribute.Int("http.status_code", clonedWriter.statusCode),
			)
			if clonedWriter.statusCode >= 400 {
				span.SetStatus(codes.Error, http.StatusText(clonedWriter.statusCode))
			}
		})
	}
}

// The Logging middleware captures any http request coming through and the response status code, and logs it.
func loggingMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clonedWriter := newResponseWriter(w)
			next.ServeHTTP(clonedWriter, r)

			// Suppress logging for static files
			if !strings.HasPrefix(r.URL.Path, "/_next") {
				ctx.systemLogger.Info("HTTP request completed", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Int("status_code", clonedWriter.statusCode), zap.String("status_text", http.StatusText(clonedWriter.statusCode)))
			}

			ctx.responseStatusCode = clonedWriter.statusCode
		})
	}
}

// auditLoggingMiddleware logs API requests to the audit log.
// It logs all failed requests, and also successful read-only (GET/HEAD) requests.
func auditLoggingMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			var actor string
			claims, err := getClaimsFromCookie(r, ctx.jwtSecret, nil)
			if err == nil {
				actor = claims.Email
			}

			action := buildActionDescription(r.Method, r.URL.Path)
			resourceID := extractResourceID(r.URL.Path)
			resourceType := extractResourceType(r.URL.Path)

			opts := []log.AuditOption{log.WithRequest(r)}
			if actor != "" {
				opts = append(opts, log.WithActor(actor))
			}
			if resourceID != "" {
				opts = append(opts, log.WithResourceID(resourceID))
			}
			if resourceType != "" {
				opts = append(opts, log.WithResourceType(resourceType))
			}

			if ctx.responseStatusCode >= 400 {
				opts = append(opts, log.WithReason(fmt.Sprintf("HTTP %d: %s", ctx.responseStatusCode, http.StatusText(ctx.responseStatusCode))))
				ctx.auditLogger.APIAction(action+" (failed)", opts...)
			}
			if ctx.responseStatusCode < 400 && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				ctx.auditLogger.APIAction(action, opts...)
			}
		})
	}
}

// buildActionDescription returns a minimal deterministic description from HTTP method and path.
// It returns "METHOD path" where the leading slash is trimmed from the path.
// Examples:
//   - GET /certificate_requests -> "GET certificate_requests"
//   - POST /users -> "POST users"
//   - DELETE /certificate_authorities/5 -> "DELETE certificate_authorities/5"
func buildActionDescription(method, path string) string {
	// Minimal, deterministic: "METHOD path-without-leading-slash"
	cleanPath := strings.Trim(path, "/")
	if cleanPath == "" {
		return method
	}
	return method + " " + cleanPath
}

// extractResourceID extracts the resource ID from the URL path if present.
// Examples:
//   - /users/123 -> "123"
//   - /certificate_authorities/5 -> "5"
func extractResourceID(path string) string {
	// Expect formats like: /{resource}/{id} or /{resource}/{id}/{subresource}
	cleanPath := strings.Trim(path, "/")
	parts := strings.Split(cleanPath, "/")
	if len(parts) > 1 {
		if _, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			return parts[1]
		}
	}
	return ""
}

// extractResourceType returns the first path segment as the resource type.
// No singularization is performed.
// Examples:
//   - /users -> "users"
//   - /certificate_requests/123 -> "certificate_requests"
func extractResourceType(path string) string {
	cleanPath := strings.Trim(path, "/")
	parts := strings.Split(cleanPath, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// requirePermission authorizes a request by verifying the caller's JWT then performing an
// OpenFGA Check against "system:notary" for each of the allowedRoles. The first matching
// role grants access; if none match, 403 Forbidden is returned.
func requirePermission(
	allowedRoles []string,
	env *HandlerDependencies,
	handler http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			env.AuditLogger.UnauthorizedAccess(
				log.WithRequest(r),
				log.WithReason("invalid or missing JWT token"),
			)
			env.SystemLogger.Warn("invalid or missing JWT token", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		userID := authorization.UserID(claims.Email)
		const systemObject = "system:notary"

		if env.AuthzRepository == nil {
			handler(w, r)
			return
		}

		allowed := false
		for _, role := range allowedRoles {
			ok, checkErr := env.AuthzRepository.Check(systemObject, role, userID)
			if checkErr != nil {
				env.SystemLogger.Error("authorization check failed", zap.Error(checkErr))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
				return
			}
			if ok {
				allowed = true
				break
			}
		}

		if !allowed {
			env.AuditLogger.AccessDenied(claims.Email, r.URL.Path, strings.Join(allowedRoles, ","),
				log.WithRequest(r),
				log.WithReason("insufficient permissions"),
			)
			env.SystemLogger.Warn("access denied due to insufficient permissions",
				zap.String("email", claims.Email),
				zap.Strings("allowed_roles", allowedRoles),
			)
			writeResponse(w, http.StatusForbidden, "forbidden: insufficient permissions", nil, env.SystemLogger)
			return
		}

		handler(w, r)
	}
}

// firstUserOrAdmin allows unauthenticated access when zero users exist (first-run setup).
// This enables the initial admin account to be created without pre-existing credentials.
// Once any user exists, it falls back to requirePermission with adminOnly access.
func firstUserOrAdmin(env *HandlerDependencies, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			env.SystemLogger.Error("failed to check user count", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		if numUsers == 0 {
			// First user — allow without authentication
			handler(w, r)
			return
		}
		// Otherwise, require admin permission
		requirePermission(adminOnly, env, handler)(w, r)
	}
}

func getClaimsFromCookie(r *http.Request, jwtSecret []byte, oidcConfig *authentication.OIDCRepository) (*authentication.NotaryJWTClaims, error) {
	c, err := r.Cookie(CookieSessionTokenKey)
	if err != nil {
		return nil, fmt.Errorf("cookie not found")
	}
	if c.Value == "" {
		return nil, fmt.Errorf("cookie value not found")
	}

	claims, err := getClaimsFromJWT(c.Value, jwtSecret, oidcConfig)
	if err != nil {
		return nil, fmt.Errorf("token is not valid: %s", err)
	}
	return claims, nil
}

func getClaimsFromJWT(rawToken string, jwtSecret []byte, oidcConfig *authentication.OIDCRepository) (*authentication.NotaryJWTClaims, error) {
	v := authentication.NewVerifier([]authentication.ProviderConfig{
		{
			Provider: oidcConfig,
			Type:     authentication.ProviderOIDC,
		},
		{
			Secret: jwtSecret,
			Type:   authentication.ProviderLocal,
		},
	})
	claims, err := v.VerifyToken(context.Background(), rawToken)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
