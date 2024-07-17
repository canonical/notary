package server

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/canonical/gocert/internal/metrics"
	"github.com/golang-jwt/jwt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	USER_ACCOUNT  = 0
	ADMIN_ACCOUNT = 1
)

type middleware func(http.Handler) http.Handler

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	metrics            *metrics.PrometheusMetrics
	jwtSecret          []byte
	firstAccountIssued bool
}

// The responseWriterCloner struct wraps the http.ResponseWriter struct, and extracts the status
// code of the response writer for the middleware to read
type responseWriterCloner struct {
	http.ResponseWriter
	statusCode int
}

// newResponseWriter returns a new ResponseWriterCloner struct
// it returns http.StatusOK by default because the http.ResponseWriter defaults to that header
// if the WriteHeader() function is never called.
func newResponseWriter(w http.ResponseWriter) *responseWriterCloner {
	return &responseWriterCloner{w, http.StatusOK}
}

// WriteHeader overrides the ResponseWriter method to duplicate the status code into the wrapper struct
func (rwc *responseWriterCloner) WriteHeader(code int) {
	rwc.statusCode = code
	rwc.ResponseWriter.WriteHeader(code)
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

// The Metrics middleware captures any request relevant to a metric and records it for prometheus.
func metricsMiddleware(ctx *middlewareContext) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := promhttp.InstrumentHandlerCounter(
				&ctx.metrics.RequestsTotal,
				promhttp.InstrumentHandlerDuration(
					&ctx.metrics.RequestsDuration,
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
				log.Println(r.Method, r.URL.Path, clonedWriter.statusCode, http.StatusText(clonedWriter.statusCode))
			}

			ctx.responseStatusCode = clonedWriter.statusCode
		})
	}
}

// authMiddleware intercepts requests that need authorization to check if the user's token exists and is
// permitted to use the endpoint
func authMiddleware(ctx *middlewareContext) middleware {
	RestrictedPaths := []struct {
		method, pathRegex     string
		SelfAuthorizedAllowed bool
	}{
		{"POST", `accounts$`, false},
		{"GET", `accounts$`, false},
		{"DELETE", `accounts\/(\d+)$`, false},
		{"GET", `accounts\/(\d+)$`, true},
		{"POST", `accounts\/(\d+)\/change_password$`, true},
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "accounts") && !ctx.firstAccountIssued {
				next.ServeHTTP(w, r)
				if strings.HasPrefix(strconv.Itoa(ctx.responseStatusCode), "2") {
					ctx.firstAccountIssued = true
				}
				return
			}
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), ctx.jwtSecret)
			if err != nil {
				logErrorAndWriteResponse(fmt.Sprintf("auth failed: %s", err.Error()), http.StatusUnauthorized, w)
				return
			}
			if claims.Permissions == USER_ACCOUNT {
				requestAllowed, err := AllowRequest(claims, r.Method, r.URL.Path, RestrictedPaths)
				if err != nil {
					logErrorAndWriteResponse(fmt.Sprintf("error processing path: %s", err.Error()), http.StatusInternalServerError, w)
					return
				}
				if !requestAllowed {
					logErrorAndWriteResponse("forbidden", http.StatusForbidden, w)
					return
				}
			}
			if r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "accounts/1") {
				logErrorAndWriteResponse("can't delete admin account", http.StatusConflict, w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getClaimsFromAuthorizationHeader(header string, jwtSecret []byte) (*jwtGocertClaims, error) {
	if header == "" {
		return nil, fmt.Errorf("authorization header not found")
	}
	bearerToken := strings.Split(header, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return nil, fmt.Errorf("authorization header couldn't be processed. The expected format is 'Bearer <token>'")
	}
	claims, err := getClaimsFromJWT(bearerToken[1], jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("token is not valid: %s", err)
	}
	return claims, nil
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
func AllowRequest(claims *jwtGocertClaims, method, path string, permissionRestrictions []struct {
	method                string
	pathRegex             string
	SelfAuthorizedAllowed bool
}) (bool, error) {
	for _, pr := range permissionRestrictions {
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
		matchedID, err := strconv.Atoi(matches[1])
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

func getClaimsFromJWT(bearerToken string, jwtSecret []byte) (*jwtGocertClaims, error) {
	claims := jwtGocertClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return &claims, nil
}
