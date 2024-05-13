package metrics_test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/canonical/gocert/internal/certdb"
	metrics "github.com/canonical/gocert/internal/metrics"
)

// TestPrometheusHandler tests that the Prometheus metrics handler responds correctly to an HTTP request.
func TestPrometheusHandler(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateReq")
	if err != nil {
		log.Fatalln(err)
	}
	m := metrics.NewMetricsSubsystem(db)

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	if !strings.Contains(recorder.Body.String(), "go_goroutines") {
		t.Errorf("handler returned an empty body")
	}
	err = db.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
