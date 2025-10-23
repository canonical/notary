package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/canonical/notary/internal/auth"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	MAX_KILOBYTES = 100
)

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	jwtSecret          []byte
	logger             *zap.Logger
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

// The Logging middleware captures any http request coming through and the response status code, and logs it.
func loggingMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clonedWriter := newResponseWriter(w)
			next.ServeHTTP(clonedWriter, r)

			// Suppress logging for static files
			if !strings.HasPrefix(r.URL.Path, "/_next") {
				ctx.logger.Info("Request", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Int("status_code", clonedWriter.statusCode), zap.String("status_text", http.StatusText(clonedWriter.statusCode)))
			}

			ctx.responseStatusCode = clonedWriter.statusCode
		})
	}
}

// requirePermission authorizes a request based on the user's given permissions.
// At least one of the required permissions must be present in the user's permissions.
func requirePermission(requiredPermissions []string, jwtSecret []byte, oidcConfig *config.OIDCConfig, handler http.HandlerFunc, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromCookie(r, jwtSecret, oidcConfig)

		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, logger)
			return
		}
		for _, perm := range requiredPermissions {
			if slices.Contains(claims.Permissions, perm) {
				handler(w, r)
				return
			}
		}
		writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing permission"), logger)
	}
}

func requirePermissionOrFirstUser(permission string, jwtSecret []byte, oidcConfig *config.OIDCConfig, db *db.Database, handler http.HandlerFunc, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := db.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, logger)
			return
		}

		// If no users exist, allow the request through (initial setup case)
		if numUsers == 0 {
			handler(w, r)
			return
		}

		// Otherwise validate permissions
		claims, err := getClaimsFromCookie(r, jwtSecret, oidcConfig)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, logger)
			return
		}

		if !slices.Contains(claims.Permissions, permission) {
			writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing required permission"), logger)
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
