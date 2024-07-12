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
	AdminOnlyPaths := []struct{ method, path string }{
		{"POST", `accounts`},
		{"GET", `accounts`},
		{"GET", `accounts\/\d+$`},
		{"DELETE", `accounts\/\d+$`},
		{"POST", `accounts\/\d+\/change_password$`},
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
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logErrorAndWriteResponse("authorization header not found", http.StatusUnauthorized, w)
				return
			}
			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
				logErrorAndWriteResponse("authorization header couldn't be processed. The expected format is 'Bearer <token>'", http.StatusUnauthorized, w)
				return
			}
			claims, err := getClaimsFromJWT(bearerToken[1], ctx.jwtSecret)
			if err != nil {
				logErrorAndWriteResponse(fmt.Sprintf("token is not valid: %s", err.Error()), http.StatusUnauthorized, w)
				return
			}
			if claims.Permissions == 0 {
				for _, v := range AdminOnlyPaths {
					matched, err := regexp.Match(v.path, []byte(r.URL.Path))
					if err != nil {
						logErrorAndWriteResponse(fmt.Sprintf("ran into issue parsing path: %s", err.Error()), http.StatusInternalServerError, w)
						return
					}
					if r.Method == v.method && matched {
						logErrorAndWriteResponse("forbidden", http.StatusForbidden, w)
						return
					}
				}
			}
			if claims.Permissions == 1 && r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "accounts/1") {
				logErrorAndWriteResponse("can't delete admin account", http.StatusConflict, w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
