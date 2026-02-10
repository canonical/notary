package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/auth"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
	"github.com/canonical/notary/internal/metrics"
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
	auditLogger        *logging.AuditLogger
	tracer             *config.Tracer
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
				writeError(w, http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge), err, logger)
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

			opts := []logging.AuditOption{logging.WithRequest(r)}
			if actor != "" {
				opts = append(opts, logging.WithActor(actor))
			}
			if resourceID != "" {
				opts = append(opts, logging.WithResourceID(resourceID))
			}
			if resourceType != "" {
				opts = append(opts, logging.WithResourceType(resourceType))
			}

			if ctx.responseStatusCode >= 400 {
				opts = append(opts, logging.WithReason(fmt.Sprintf("HTTP %d: %s", ctx.responseStatusCode, http.StatusText(ctx.responseStatusCode))))
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

// requirePermission authorizes a request based on the user's given permissions.
// At least one of the required permissions must be present in the user's permissions.
func requirePermission(
	requiredPermissions []string,
	jwtSecret []byte,
	oidcConfig *config.OIDCConfig,
	handler http.HandlerFunc,
	systemLogger *zap.Logger,
	auditLogger *logging.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromRequest(r, jwtSecret, oidcConfig)
		if err != nil {
			auditLogger.UnauthorizedAccess(
				logging.WithRequest(r),
				logging.WithReason("invalid or missing JWT token"),
			)
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, systemLogger)
			return
		}

		for _, perm := range requiredPermissions {
			if slices.Contains(claims.Permissions, perm) {
				handler(w, r)
				return
			}
		}
		auditLogger.AccessDenied(claims.Email, r.URL.Path, strings.Join(requiredPermissions, ","),
			logging.WithRequest(r),
			logging.WithReason("insufficient permissions"),
		)
		writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing permission"), systemLogger)
	}
}

func requirePermissionOrFirstUser(permission string, jwtSecret []byte, oidcConfig *config.OIDCConfig, db *db.Database, handler http.HandlerFunc, systemLogger *zap.Logger, auditLogger *logging.AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := db.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, systemLogger)
			return
		}

		if numUsers == 0 {
			handler(w, r)
			return
		}

		claims, err := getClaimsFromRequest(r, jwtSecret, oidcConfig)
		if err != nil {
			auditLogger.UnauthorizedAccess(
				logging.WithRequest(r),
				logging.WithReason("invalid or missing JWT token"),
			)
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, systemLogger)
			return
		}

		if !slices.Contains(claims.Permissions, permission) {
			auditLogger.AccessDenied(claims.Email, r.URL.Path, permission,
				logging.WithRequest(r),
				logging.WithReason("insufficient permissions"),
			)
			writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing required permission"), systemLogger)
			return
		}

		handler(w, r)
	}
}

func getClaimsFromCookie(r *http.Request, jwtSecret []byte, oidcConfig *config.OIDCConfig) (*auth.NotaryJWTClaims, error) {
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

func getClaimsFromRequest(r *http.Request, jwtSecret []byte, oidcConfig *config.OIDCConfig) (*auth.NotaryJWTClaims, error) {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		return getClaimsFromAuthorizationHeader(authHeader, jwtSecret, oidcConfig)
	}
	return getClaimsFromCookie(r, jwtSecret, oidcConfig)
}

func getClaimsFromAuthorizationHeader(authHeader string, jwtSecret []byte, oidcConfig *config.OIDCConfig) (*auth.NotaryJWTClaims, error) {
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header not found")
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid authorization header")
	}

	claims, err := getClaimsFromJWT(parts[1], jwtSecret, oidcConfig)
	if err != nil {
		return nil, fmt.Errorf("token is not valid: %s", err)
	}

	return claims, nil
}

func getClaimsFromJWT(rawToken string, jwtSecret []byte, oidcConfig *config.OIDCConfig) (*auth.NotaryJWTClaims, error) {
	v := auth.NewVerifier([]auth.ProviderConfig{
		{
			Provider: oidcConfig,
			Type:     auth.ProviderOIDC,
		},
		{
			Secret: jwtSecret,
			Type:   auth.ProviderLocal,
		},
	})
	claims, err := v.VerifyToken(context.Background(), rawToken)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
