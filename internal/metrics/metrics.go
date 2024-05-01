package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsHandler interface {
	http.Handler
}

// PrometheusHandler implements the MetricsHandler interface.
type PrometheusHandler struct {
	registry *prometheus.Registry
}

// Returns a new PrometheusHandler.
func NewPrometheusHandler() MetricsHandler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	return &PrometheusHandler{
		registry: registry,
	}
}

// ServeHTTP implements the http.Handler interface, allowing the PrometheusHandler to handle HTTP requests.
func (p *PrometheusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
