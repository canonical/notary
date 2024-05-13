package metrics

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/canonical/gocert/internal/certdb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	http.Handler
	registry                       *prometheus.Registry
	CertificateRequests            prometheus.Gauge
	OutstandingCertificateRequests prometheus.Gauge
	Certificates                   prometheus.Gauge
	CertificatesExpiringIn1Day     prometheus.Gauge
	CertificatesExpiringIn7Days    prometheus.Gauge
	CertificatesExpiringIn30Days   prometheus.Gauge
	CertificatesExpiringIn90Days   prometheus.Gauge
	ExpiredCertificates            prometheus.Gauge
}

// NewMetricsSubsystem returns the metrics endpoint HTTP handler and the Prometheus metrics for the server and middleware.
func NewMetricsSubsystem(db *certdb.CertificateRequestsRepository) *PrometheusMetrics {
	metricsBackend, err := newPrometheusMetrics(db)
	if err != nil {
		log.Println(errors.Join(errors.New("error generating metrics repository: "), err))
	}
	metricsBackend.Handler = promhttp.HandlerFor(metricsBackend.registry, promhttp.HandlerOpts{})
	return metricsBackend
}

// newPrometheusMetrics reads the status of the database, calculates all of the values of the metrics,
// registers these metrics to the prometheus registry, and returns the registry and the metrics.
// The registry and metrics can be modified from this struct from anywhere in the codebase.
func newPrometheusMetrics(db *certdb.CertificateRequestsRepository) (*PrometheusMetrics, error) {
	csrs, err := db.RetrieveAll()
	if err != nil {
		return nil, errors.Join(errors.New("could not retrieve certs for metrics: "), err)
	}
	m := &PrometheusMetrics{
		registry:                       prometheus.NewRegistry(),
		CertificateRequests:            certificateRequestsMetric(),
		OutstandingCertificateRequests: outstandingCertificateRequestsMetric(),
		Certificates:                   certificatesMetric(),
		ExpiredCertificates:            expiredCertificatesMetric(),
		CertificatesExpiringIn1Day:     certificatesExpiringIn1DayMetric(),
		CertificatesExpiringIn7Days:    certificatesExpiringIn7DaysMetric(),
		CertificatesExpiringIn30Days:   certificatesExpiringIn30DaysMetric(),
		CertificatesExpiringIn90Days:   certificatesExpiringIn90DaysMetric(),
	}
	m.registry.MustRegister(m.CertificateRequests)
	m.registry.MustRegister(m.OutstandingCertificateRequests)
	m.registry.MustRegister(m.Certificates)
	m.registry.MustRegister(m.ExpiredCertificates)
	m.registry.MustRegister(m.CertificatesExpiringIn1Day)
	m.registry.MustRegister(m.CertificatesExpiringIn7Days)
	m.registry.MustRegister(m.CertificatesExpiringIn30Days)
	m.registry.MustRegister(m.CertificatesExpiringIn90Days)

	m.generateMetrics(csrs)
	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m, nil
}

// generateMetrics receives the live list of csrs to calculate the most recent values for the metrics
// defined for prometheus
func (pm *PrometheusMetrics) generateMetrics(csrs []certdb.CertificateRequest) {
	// TODO: This can run every 24 hours also to make sure we update the expiring in X day metrics.
	var csrCount int = len(csrs)
	var outstandingCSRCount int
	var certCount int
	var expiredCertCount int
	var expiringIn1DayCertCount int
	var expiringIn7DaysCertCount int
	var expiringIn30DaysCertCount int
	var expiringIn90DaysCertCount int
	for _, entry := range csrs {
		if entry.Certificate == "" {
			outstandingCSRCount += 1
		}
		if entry.Certificate != "" && entry.Certificate != "rejected" {
			certCount += 1
		}
		expiryDate := certificateExpiryDate(entry.Certificate)
		daysRemaining := time.Until(expiryDate).Hours() / 24
		if daysRemaining < 0 {
			expiredCertCount += 1
		} else {
			if daysRemaining < 1 {
				expiringIn1DayCertCount += 1
			}
			if daysRemaining < 7 {
				expiringIn7DaysCertCount += 1
			}
			if daysRemaining < 30 {
				expiringIn30DaysCertCount += 1
			}
			if daysRemaining < 90 {
				expiringIn90DaysCertCount += 1
			}
		}
	}
	pm.CertificateRequests.Set(float64(csrCount))
	pm.OutstandingCertificateRequests.Set(float64(outstandingCSRCount))
	pm.Certificates.Set(float64(certCount))
	pm.ExpiredCertificates.Set(float64(expiredCertCount))
	pm.CertificatesExpiringIn1Day.Set(float64(expiringIn1DayCertCount))
	pm.CertificatesExpiringIn7Days.Set(float64(expiringIn7DaysCertCount))
	pm.CertificatesExpiringIn30Days.Set(float64(expiringIn30DaysCertCount))
	pm.CertificatesExpiringIn90Days.Set(float64(expiringIn90DaysCertCount))
}

func certificateRequestsMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificate_requests",
		Help:      "Total number of certificate requests",
	})
	return metric
}

func outstandingCertificateRequestsMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "outstanding_certificate_requests",
		Help:      "Number of outstanding certificate requests",
	})
	return metric
}

func certificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates",
		Help:      "Total number of certificates provided to certificate requests",
	})
	return metric
}

func expiredCertificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates_expired",
		Help:      "Number of expired certificates",
	})
	return metric
}

func certificatesExpiringIn1DayMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates_expiring_in_1_day",
		Help:      "Number of certificates expiring in less than 1 day",
	})
	return metric
}

func certificatesExpiringIn7DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates_expiring_in_7_days",
		Help:      "Number of certificates expiring in less than 7 days",
	})
	return metric
}
func certificatesExpiringIn30DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates_expiring_in_30_days",
		Help:      "Number of certificates expiring in less than 30 days",
	})
	return metric
}

func certificatesExpiringIn90DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "TODO",
		Subsystem: "TODO",
		Name:      "certificates_expiring_in_90_days",
		Help:      "Number of certificates expiring in less than 90 days",
	})
	return metric
}

func certificateExpiryDate(certString string) time.Time {
	certBlock, _ := pem.Decode([]byte(certString))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	// TODO: cert.NotAfter can exist in a wrong cert. We should catch that at the db level validation
	return cert.NotAfter
}
