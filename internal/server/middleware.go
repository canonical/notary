package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/metrics"
	"github.com/golang-jwt/jwt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	UserPermission  = 0
	AdminPermission = 1
)

type middleware func(http.Handler) http.Handler

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	jwtSecret          []byte
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
				log.Println(r.Method, r.URL.Path, clonedWriter.statusCode, http.StatusText(clonedWriter.statusCode))
			}

			ctx.responseStatusCode = clonedWriter.statusCode
		})
	}
}

// The adminOnly middleware checks if the user has admin permissions before allowing access to the handler.
func adminOnly(jwtSecret []byte, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), jwtSecret)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if claims.Permissions != AdminPermission {
			writeError(w, http.StatusForbidden, "forbidden: admin access required")
			return
		}

		handler(w, r)
	}
}

// The adminOrUser middleware checks if the user has admin or user permissions before allowing access to the handler.
func adminOrUser(jwtSecret []byte, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), jwtSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if claims.Permissions != AdminPermission && claims.Permissions != UserPermission {
			writeError(w, http.StatusForbidden, "forbidden: admin or user access required")
			return
		}

		handler(w, r)
	}
}

// The adminOrMe middleware checks if the user has admin permissions or if the user is the same user before allowing access to the handler.
func adminOrMe(jwtSecret []byte, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), jwtSecret)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if claims.Permissions != AdminPermission {
			if r.PathValue("id") != "me" && strconv.Itoa(claims.ID) != r.PathValue("id") {
				writeError(w, http.StatusForbidden, "forbidden: admin access required")
				return
			}
		}

		handler(w, r)
	}
}

// The adminOrFirstUser middleware checks if the user has admin permissions or if the user is the first user before allowing access to the handler.
func adminOrFirstUser(jwtSecret []byte, db *db.Database, handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := db.NumUsers()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}

		if numUsers > 0 {
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), jwtSecret)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			if claims.Permissions != AdminPermission && numUsers > 0 {
				writeError(w, http.StatusForbidden, "forbidden: admin access required")
				return
			}
		}
		handler(w, r)
	}
}

func getClaimsFromAuthorizationHeader(header string, jwtSecret []byte) (*jwtNotaryClaims, error) {
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

func getClaimsFromJWT(bearerToken string, jwtSecret []byte) (*jwtNotaryClaims, error) {
	claims := jwtNotaryClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return &claims, nil
}
