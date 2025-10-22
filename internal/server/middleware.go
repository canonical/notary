package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/auth"
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

// authenticationMiddleware extracts the claims from the request and loads it into the claims into the context.
func authenticationMiddleware(jwtSecret []byte, logger *zap.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := getClaimsFromCookie(r, jwtSecret)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized", err, logger)
				return
			}

			ctx := context.WithValue(r.Context(), "claims", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
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

func requirePermission(permission string, jwtSecret []byte, handler http.HandlerFunc, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromCookie(r, jwtSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, logger)
			return
		}
		roleID := claims.RoleID
		permissions, ok := PermissionsByRole[roleID]
		if !ok {
			writeError(w, http.StatusForbidden, "forbidden: unknown role", errors.New("role not found"), logger)
			return
		}

		if !hasPermission(permissions, permission) {
			writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing permission"), logger)
			return
		}

		handler(w, r)
	}
}

func hasPermission(userPermissions []string, required string) bool {
	for _, p := range userPermissions {
		if p == required || p == "*" {
			return true
		}
	}
	return false
}

func requirePermissionOrFirstUser(permission string, jwtSecret []byte, db *db.Database, handler http.HandlerFunc, logger *zap.Logger) http.HandlerFunc {
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
		claims, err := getClaimsFromCookie(r, jwtSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, logger)
			return
		}

		permissions, ok := PermissionsByRole[claims.RoleID]
		if !ok || !hasPermission(permissions, permission) {
			writeError(w, http.StatusForbidden, "forbidden: insufficient permissions", errors.New("missing required permission"), logger)
			return
		}

		handler(w, r)
	}
}

// AllowRequest looks at the user data to determine the following things:
// The first question is "Is this user trying to access a path that's restricted?"
//
// There are two types of restricted paths: admin only paths that only admins can access, and self authorized paths,
// which users are allowed to use only if they are taking an action on their own user ID. The second question is
// "If the path requires an ID, is the user attempting to access their own ID?"
//
// For all endpoints and permission permutations, there are only 2 cases when users are allowed to use endpoints:
// If the URL path is not restricted to admins
// If the URL path is restricted to self authorized endpoints, and the user is taking action with their own ID
// This function validates that the user the with the given claims is allowed to use the endpoints by passing the above checks.
func AllowRequest(claims *jwtNotaryClaims, method, path string) (bool, error) {
	restrictedPaths := []struct {
		method, pathRegex     string
		SelfAuthorizedAllowed bool
	}{
		{"POST", `accounts$`, false},
		{"GET", `accounts$`, false},
		{"DELETE", `accounts\/(\d+)$`, false},
		{"GET", `accounts\/(\d+)$`, true},
		{"POST", `accounts\/(\d+)\/change_password$`, true},
	}
	for _, pr := range restrictedPaths {
		regexChallenge, err := regexp.Compile(pr.pathRegex)
		if err != nil {
			return false, fmt.Errorf("regex couldn't compile: %s", err)
		}
		matches := regexChallenge.FindStringSubmatch(path)
		restrictedPathMatchedToRequestedPath := len(matches) > 0 && method == pr.method
		if !restrictedPathMatchedToRequestedPath {
			continue
		}
		if !pr.SelfAuthorizedAllowed {
			return false, nil
		}
		matchedID, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return true, fmt.Errorf("error converting url id to string: %s", err)
		}
		var requestedIDMatchesTheClaimant bool
		if matchedID == claims.ID {
			requestedIDMatchesTheClaimant = true
		}
		IDRequiredForPath := len(matches) > 1
		if IDRequiredForPath && !requestedIDMatchesTheClaimant {
			return false, nil
		}
		return true, nil
	}
	return true, nil
}

func getClaimsFromCookie(r *http.Request, jwtSecret []byte) (*jwtNotaryClaims, error) {
	c, err := r.Cookie(CookieSessionTokenKey)
	if err != nil {
		return nil, fmt.Errorf("cookie not found")
	}
	if c.Value == "" {
		return nil, fmt.Errorf("cookie value not found")
	}

	claims, err := getClaimsFromJWT(c.Value, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("token is not valid: %s", err)
	}
	return claims, nil
}

func getClaimsFromJWT(rawToken string, jwtSecret []byte) (*jwtNotaryClaims, error) {
	v := auth.NewVerifier([]auth.ProviderConfig{
		{
			Issuer:   "dev-2g8fk6k6vajh1qod.us.auth0.com", // TODO: get this from the config
			ClientID: "ib875DYuqa5qu5a5x7AYKfrzsOyUrZvR",  // TODO: get this from the config
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
	id := claims["id"].(float64) //TODO: temp: remove this and just json unmarshall correctly into the struct inside verifytoken
	roleid := claims["role_id"].(float64)
	notaryClaims := jwtNotaryClaims{
		ID:     int64(id),
		Email:  claims["email"].(string),
		RoleID: RoleID(roleid),
	}
	return &notaryClaims, nil
}
