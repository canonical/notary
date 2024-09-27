package server

import "net/http"

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     0,
	}
}

func (mw *responseWriter) WriteHeader(statusCode int) {
	mw.ResponseWriter.WriteHeader(statusCode)
	if mw.statusCode == 0 {
		mw.statusCode = statusCode
	}
}

func (mw *responseWriter) Write(b []byte) (int, error) {
	return mw.ResponseWriter.Write(b)
}

func (mw *responseWriter) Unwrap() http.ResponseWriter {
	return mw.ResponseWriter
}
