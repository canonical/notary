package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metrics "github.com/canonical/gocert/internal/metrics"
)

// TestPrometheusHandler tests that the Prometheus metrics handler responds correctly to an HTTP request.
func TestPrometheusHandler(t *testing.T) {
	handler := metrics.NewPrometheusHandler()

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	if !strings.Contains(recorder.Body.String(), "go_goroutines") {
		t.Errorf("handler returned an empty body")
	}
}
