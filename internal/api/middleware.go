package server

import (
	"log"
	"net/http"

	"github.com/canonical/gocert/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type middleware func(http.Handler) http.Handler

// The middlewareContext type helps middleware receive and pass along information through the middleware chain.
type middlewareContext struct {
	responseStatusCode int
	metrics            *metrics.PrometheusMetrics
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
			clonedWwriter := newResponseWriter(w)
			next.ServeHTTP(w, r)
			log.Println(r.Method, r.URL.Path, clonedWwriter.statusCode, http.StatusText(clonedWwriter.statusCode))
			ctx.responseStatusCode = clonedWwriter.statusCode
		})
	}
}
