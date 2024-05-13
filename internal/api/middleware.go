package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/canonical/gocert/internal/metrics"
)

type Middleware func(http.Handler) http.Handler

// The MiddlewareContext type helps middleware receive and pass along information through the middleware chain.
type MiddlewareContext struct {
	responseStatusCode int
	metrics            *metrics.PrometheusMetrics
}

// The ResponseWriterCloner struct wraps the http.ResponseWriter struct, and extracts the status
// code of the response writer for the middleware to read
type ResponseWriterCloner struct {
	http.ResponseWriter
	statusCode int
}

// NewResponseWriter returns a new ResponseWriterCloner struct
// it returns http.StatusOK by default because the http.ResponseWriter defaults to that header
// if the WriteHeader() function is never called.
func NewResponseWriter(w http.ResponseWriter) *ResponseWriterCloner {
	return &ResponseWriterCloner{w, http.StatusOK}
}

// WriteHeader overrides the ResponseWriter method to duplicate the status code into the wrapper struct
func (rwc *ResponseWriterCloner) WriteHeader(code int) {
	rwc.statusCode = code
	rwc.ResponseWriter.WriteHeader(code)
}

// createMiddlewareStack chains the given middleware functions to wrap the api.
// Each middleware functions calls next.ServeHTTP in order to resume the chain of execution.
// The order the middleware functions are given to createMiddlewareStack matters.
// Any code before next.ServeHTTP is called is executed in the given middleware's order.
// Any code after next.ServeHTTP is called is executed in the given middleware's reverse order.
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
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/certificate_requests") {
				ctx.metrics.CertificateRequests.Inc()
			}
			if r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "/certificate_requests") {
				ctx.metrics.CertificateRequests.Dec()
			}
		})
	}
}

// The Logging middleware captures any http request coming through and the response status code, and logs it.
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
