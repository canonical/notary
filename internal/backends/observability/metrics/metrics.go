package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type PrometheusMetrics struct {
	http.Handler
	registry                       *prometheus.Registry
	cancel                         context.CancelFunc
	CertificateRequests            prometheus.Gauge
	OutstandingCertificateRequests prometheus.Gauge
	Certificates                   prometheus.Gauge
	CertificatesExpiringIn1Day     prometheus.Gauge
	CertificatesExpiringIn7Days    prometheus.Gauge
	CertificatesExpiringIn30Days   prometheus.Gauge
	CertificatesExpiringIn90Days   prometheus.Gauge
	ExpiredCertificates            prometheus.Gauge
	EnabledCACertificates          prometheus.Gauge
	ExpiredCACertificates          prometheus.Gauge
	DisabledCACertificates         prometheus.Gauge
	EnabledCARemainingDays         prometheus.GaugeVec
	CertificateNotBefore           *prometheus.GaugeVec
	CertificateNotAfter            *prometheus.GaugeVec
	CertificateValidityConsumed    *prometheus.GaugeVec
	CertificatesValidityConsumed   *prometheus.GaugeVec

	RequestsTotal    prometheus.CounterVec
	RequestsDuration prometheus.HistogramVec
}

// NewMetricsSubsystem returns the metrics endpoint HTTP handler and the Prometheus metrics collectors for the server and middleware.
func NewMetricsSubsystem(db *db.DatabaseRepository, logger *zap.Logger) *PrometheusMetrics {
	metricsBackend := newPrometheusMetrics()
	metricsBackend.Handler = promhttp.HandlerFor(metricsBackend.registry, promhttp.HandlerOpts{})

	ctx, cancel := context.WithCancel(context.Background())
	metricsBackend.cancel = cancel

	err := collectMetrics(db, metricsBackend)
	if err != nil {
		logger.Error("Error collecting metrics", zap.String("err", err.Error()))
	}

	ticker := time.NewTicker(120 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err = collectMetrics(db, metricsBackend)
				if err != nil {
					logger.Error("Error collecting metrics", zap.String("err", err.Error()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return metricsBackend
}

// Helper function to collect metrics and handle errors properly
func collectMetrics(db *db.DatabaseRepository, metrics *PrometheusMetrics) error {
	csrs, err := db.ListCertificateRequestWithCertificates()
	if err != nil {
		return fmt.Errorf("collecting certificate metrics: %w", err)
	}
	metrics.GenerateCertificateMetrics(csrs)

	cas, err := db.ListDenormalizedCertificateAuthorities()
	if err != nil {
		return fmt.Errorf("collecting CA certificate metrics: %w", err)
	}
	metrics.GenerateCACertificateMetrics(cas)
	return nil
}

// Close properly shuts down the metrics goroutine
func (pm *PrometheusMetrics) Close() {
	if pm.cancel != nil {
		pm.cancel()
	}
}

// newPrometheusMetrics reads the status of the database, calculates all of the values of the metrics,
// registers these metrics to the prometheus registry, and returns the registry and the metrics.
// The registry and metrics can be modified from this struct from anywhere in the codebase.
func newPrometheusMetrics() *PrometheusMetrics {
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
		EnabledCACertificates:          enabledCACertificatesMetric(),
		RequestsTotal:                  requestsTotalMetric(),
		RequestsDuration:               requestDurationMetric(),
		ExpiredCACertificates:          expiredCACertificatesMetric(),
		DisabledCACertificates:         disabledCACertificatesMetric(),
		EnabledCARemainingDays:         enabledCARemainingDaysMetric(),
		CertificateNotBefore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certificate_not_before_timestamp_seconds",
			Help: "Start of leaf certificate validity as a Unix timestamp in seconds",
		}, []string{"csr_id"}),
		CertificateNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certificate_not_after_timestamp_seconds",
			Help: "End of leaf certificate validity as a Unix timestamp in seconds",
		}, []string{"csr_id"}),
		CertificateValidityConsumed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certificate_validity_consumed_ratio",
			Help: "Fraction of leaf certificate validity elapsed; negative before validity starts and at least one at expiry",
		}, []string{"csr_id"}),
		CertificatesValidityConsumed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certificates_validity_consumed",
			Help: "Number of currently valid leaf certificates at or above the cumulative consumed validity threshold",
		}, []string{"threshold"}),
	}
	m.registry.MustRegister(m.CertificateRequests)
	m.registry.MustRegister(m.OutstandingCertificateRequests)
	m.registry.MustRegister(m.Certificates)
	m.registry.MustRegister(m.ExpiredCertificates)
	m.registry.MustRegister(m.CertificatesExpiringIn1Day)
	m.registry.MustRegister(m.CertificatesExpiringIn7Days)
	m.registry.MustRegister(m.CertificatesExpiringIn30Days)
	m.registry.MustRegister(m.CertificatesExpiringIn90Days)
	m.registry.MustRegister(m.EnabledCACertificates)
	m.registry.MustRegister(m.ExpiredCACertificates)
	m.registry.MustRegister(m.DisabledCACertificates)
	m.registry.MustRegister(m.EnabledCARemainingDays)
	m.registry.MustRegister(m.CertificateNotBefore)
	m.registry.MustRegister(m.CertificateNotAfter)
	m.registry.MustRegister(m.CertificateValidityConsumed)
	m.registry.MustRegister(m.CertificatesValidityConsumed)

	m.registry.MustRegister(m.RequestsTotal)
	m.registry.MustRegister(m.RequestsDuration)

	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// GenerateCertificateMetrics receives the live list of csrs to calculate the most recent values for the metrics
// defined for prometheus
func (pm *PrometheusMetrics) GenerateCertificateMetrics(csrs []db.CertificateRequestWithChain) {
	pm.generateCertificateMetrics(csrs, time.Now())
}

func (pm *PrometheusMetrics) generateCertificateMetrics(csrs []db.CertificateRequestWithChain, now time.Time) {
	pm.CertificateNotBefore.Reset()
	pm.CertificateNotAfter.Reset()
	pm.CertificateValidityConsumed.Reset()
	thresholds := []struct {
		label string
		ratio float64
		count float64
	}{
		{label: "0.65", ratio: 0.65},
		{label: "0.90", ratio: 0.90},
		{label: "0.95", ratio: 0.95},
	}
	var csrCount = float64(len(csrs))
	var outstandingCSRCount float64
	var certCount float64
	var expiredCertCount float64
	var expiringIn1DayCertCount float64
	var expiringIn7DaysCertCount float64
	var expiringIn30DaysCertCount float64
	var expiringIn90DaysCertCount float64
	for _, entry := range csrs {
		if entry.CertificateChain == "" {
			outstandingCSRCount += 1
			continue
		}
		if entry.Status == "Rejected" || entry.Status == "Revoked" {
			continue
		}
		certCount += 1
		certBlock, _ := pem.Decode([]byte(entry.CertificateChain))
		if certBlock == nil {
			continue
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			continue
		}
		csrID := fmt.Sprintf("%d", entry.CSR_ID)
		pm.CertificateNotBefore.WithLabelValues(csrID).Set(float64(certificate.NotBefore.Unix()))
		pm.CertificateNotAfter.WithLabelValues(csrID).Set(float64(certificate.NotAfter.Unix()))
		validity := certificate.NotAfter.Sub(certificate.NotBefore)
		if validity > 0 {
			ratio := float64(now.Sub(certificate.NotBefore)) / float64(validity)
			pm.CertificateValidityConsumed.WithLabelValues(csrID).Set(ratio)
			if !now.Before(certificate.NotBefore) && now.Before(certificate.NotAfter) {
				for index := range thresholds {
					if ratio >= thresholds[index].ratio {
						thresholds[index].count++
					}
				}
			}
		}
		daysRemaining := math.Floor(certificate.NotAfter.Sub(now).Hours() / 24)
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
	pm.CertificateRequests.Set(csrCount)
	pm.OutstandingCertificateRequests.Set(outstandingCSRCount)
	pm.Certificates.Set(certCount)
	pm.ExpiredCertificates.Set(expiredCertCount)
	pm.CertificatesExpiringIn1Day.Set(expiringIn1DayCertCount)
	pm.CertificatesExpiringIn7Days.Set(expiringIn7DaysCertCount)
	pm.CertificatesExpiringIn30Days.Set(expiringIn30DaysCertCount)
	pm.CertificatesExpiringIn90Days.Set(expiringIn90DaysCertCount)
	for _, threshold := range thresholds {
		pm.CertificatesValidityConsumed.WithLabelValues(threshold.label).Set(threshold.count)
	}
}

func (pm *PrometheusMetrics) GenerateCACertificateMetrics(cas []db.CertificateAuthorityDenormalized) {
	var enabledCACertCount float64
	var disabledCACertCount float64
	var expiredCACertCount float64

	pm.EnabledCARemainingDays.Reset()

	for _, entry := range cas {
		if entry.CertificateChain != "" {
			expiryDate := certificateExpiryDate(entry.CertificateChain)
			if expiryDate.Before(time.Now()) {
				expiredCACertCount += 1
			}
		}
		if entry.Enabled {
			enabledCACertCount += 1
			if entry.CertificateChain != "" {
				expiryDate := certificateExpiryDate(entry.CertificateChain)
				daysRemaining := math.Floor(time.Until(expiryDate).Hours() / 24)

				pm.EnabledCARemainingDays.With(prometheus.Labels{
					"ca_id": fmt.Sprintf("%d", entry.CertificateAuthorityID),
				}).Set(daysRemaining)
			}
		} else {
			disabledCACertCount += 1
		}
	}
	pm.EnabledCACertificates.Set(enabledCACertCount)
	pm.ExpiredCACertificates.Set(expiredCACertCount)
	pm.DisabledCACertificates.Set(disabledCACertCount)
}

func certificateRequestsMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificate_requests",
		Help: "Total number of certificate requests",
	})
	return metric
}

func outstandingCertificateRequestsMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "outstanding_certificate_requests",
		Help: "Number of outstanding certificate requests",
	})
	return metric
}

func certificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates",
		Help: "Total number of certificates provided to certificate requests",
	})
	return metric
}

func expiredCertificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates_expired",
		Help: "Number of expired certificates",
	})
	return metric
}

func certificatesExpiringIn1DayMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates_expiring_in_1_day",
		Help: "Number of certificates expiring in less than 1 day",
	})
	return metric
}

func certificatesExpiringIn7DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates_expiring_in_7_days",
		Help: "Number of certificates expiring in less than 7 days",
	})
	return metric
}

func certificatesExpiringIn30DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates_expiring_in_30_days",
		Help: "Number of certificates expiring in less than 30 days",
	})
	return metric
}

func certificatesExpiringIn90DaysMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certificates_expiring_in_90_days",
		Help: "Number of certificates expiring in less than 90 days",
	})
	return metric
}

func enabledCACertificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "enabled_ca_certificates",
		Help: "Number of enabled CA certificates",
	})
	return metric
}

func expiredCACertificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "expired_ca_certificates",
		Help: "Number of expired CA certificates",
	})
	return metric
}

func disabledCACertificatesMetric() prometheus.Gauge {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "disabled_ca_certificates",
		Help: "Number of disabled CA certificates",
	})
	return metric
}

func enabledCARemainingDaysMetric() prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "enabled_ca_certificate_validity_days",
			Help: "Number of days remaining until enabled CA certificates expire",
		},
		[]string{"ca_id"},
	)
	return *metric
}

func requestsTotalMetric() prometheus.CounterVec {
	metric := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Tracks the number of HTTP requests.",
		}, []string{"method", "code"},
	)
	return *metric
}

func requestDurationMetric() prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Tracks the latencies for HTTP requests.",
			Buckets: prometheus.ExponentialBuckets(0.1, 1.5, 5),
		}, []string{"method", "code"},
	)
	return *metric
}

func certificateExpiryDate(certString string) time.Time {
	certBlock, _ := pem.Decode([]byte(certString))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	return cert.NotAfter
}
