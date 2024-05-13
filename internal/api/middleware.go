package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/canonical/gocert/internal/metrics"
)

type Middleware func(http.Handler) http.Handler

// The MiddlewareContext type helps middleware pass along information through the chain.
type MiddlewareContext struct {
	responseStatusCode int
	metrics            *metrics.PrometheusMetrics
}

// The ResponseWriterCloner struct implements the http.ResponseWriter class, and copies the status
// code of the response for the middleware to be able to read the responses.
type ResponseWriterCloner struct {
	http.ResponseWriter
	statusCode int
}

// NewResponseWriter returns a new ResponseWriterCloner struct
func NewResponseWriter(w http.ResponseWriter) *ResponseWriterCloner {
	return &ResponseWriterCloner{w, http.StatusOK}
}

// WriteHeader duplicates the status code into the cloner struct for reading
func (rwc *ResponseWriterCloner) WriteHeader(code int) {
	rwc.statusCode = code
	rwc.ResponseWriter.WriteHeader(code)
}

// createMiddlewareStack chains given middleware for the server.
// Each middleware functions calls next.ServeHTTP in order to resume the chain of execution.
// The order these functions are given to createMiddlewareStack matters.
// The functions will run the code before next.ServeHTTP in order.
// The functions will run the code after next.ServeHTTP in reverse order.
func createMiddlewareStack(middleware ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middleware) - 1; i >= 0; i-- {
			mw := middleware[i]
			next = mw(next)
		}
		return next
	}
}

// The Metrics middleware captures any request relevant to a metric and records it for prometheus.
func Metrics(ctx *MiddlewareContext) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if ctx.responseStatusCode/100 != 2 {
				return
			}
			if r.Method == "POST" && r.URL.Path == "/api/v1/certificate_requests" {
				ctx.metrics.CertificateRequests.Inc()
			}
			if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/v1/certificate_requests") {
				ctx.metrics.CertificateRequests.Dec()
			}
		})
	}
}

// The logging middleware captures any http request coming through, and logs it.
func Logging(ctx *MiddlewareContext) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clonedWwriter := NewResponseWriter(w)
			next.ServeHTTP(w, r)
			log.Println(r.Method, r.URL.Path, clonedWwriter.statusCode, http.StatusText(clonedWwriter.statusCode))
			ctx.responseStatusCode = clonedWwriter.statusCode
		})
	}
}
