package server

import (
	"log"
	"net/http"
)

type Middleware func(http.Handler) http.Handler

// The Context type helps middleware pass along information through the chain.
type Context struct {
	responseStatusCode int
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

// The Metrics middleware captures any request relevant to a metric and records it for prometheus.
func Metrics(ctx *Context) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if ctx.responseStatusCode != 200 {
				return
			}
		})
	}
}

// The logging middleware captures any http request coming through, and logs it.
func Logging(ctx *Context) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clonedWwriter := NewResponseWriter(w)
			next.ServeHTTP(w, r)
			log.Println(r.Method, r.URL.Path, clonedWwriter.statusCode, http.StatusText(clonedWwriter.statusCode))
			ctx.responseStatusCode = clonedWwriter.statusCode
		})
	}
}
