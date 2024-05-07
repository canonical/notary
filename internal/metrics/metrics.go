package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Returns an HTTP handler for Prometheus metrics.
func NewPrometheusMetricsHandler() http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	prometheusHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return prometheusHandler
}
