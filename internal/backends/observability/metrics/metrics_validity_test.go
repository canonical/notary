package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
)

func validityCertificate(t *testing.T, start, end time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: start, NotAfter: end}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func gatheredGauges(t *testing.T, metrics *PrometheusMetrics, name, label string) map[string]float64 {
	t.Helper()
	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			for _, pair := range metric.Label {
				if pair.GetName() == label {
					values[pair.GetValue()] = metric.GetGauge().GetValue()
				}
			}
		}
	}
	return values
}

func TestCertificateValidityMetrics(t *testing.T) {
	now := time.Unix(1800000000, 0)
	metrics := newPrometheusMetrics()
	var requests []db.CertificateRequestWithChain
	ratios := []float64{0.64, 0.65, 0.90, 0.95, 1, 1.10, -0.10}
	for index, ratio := range ratios {
		start := now.Add(-time.Duration(ratio*1000) * time.Second)
		requests = append(requests, db.CertificateRequestWithChain{
			CSR_ID: int64(index + 1), Status: "Signed",
			CertificateChain: validityCertificate(t, start, start.Add(1000*time.Second)),
		})
	}
	requests = append(requests,
		db.CertificateRequestWithChain{CSR_ID: 8, Status: "Revoked", CertificateChain: requests[3].CertificateChain},
		db.CertificateRequestWithChain{CSR_ID: 9, Status: "Rejected", CertificateChain: requests[3].CertificateChain},
		db.CertificateRequestWithChain{CSR_ID: 10, Status: "Pending"},
		db.CertificateRequestWithChain{CSR_ID: 11, CertificateChain: "invalid PEM"},
		db.CertificateRequestWithChain{CSR_ID: 12, CertificateChain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}))},
		db.CertificateRequestWithChain{CSR_ID: 13, CertificateChain: validityCertificate(t, now, now)},
		db.CertificateRequestWithChain{CSR_ID: 14, CertificateChain: validityCertificate(t, now, now.Add(-time.Second))},
	)
	metrics.generateCertificateMetrics(requests, now)
	counts := gatheredGauges(t, metrics, "certificates_validity_consumed", "threshold")
	for label, expected := range map[string]float64{"0.65": 3, "0.90": 2, "0.95": 1} {
		if actual, exists := counts[label]; !exists || actual != expected {
			t.Errorf("threshold %s: got %v (present %v), want %v", label, actual, exists, expected)
		}
	}
	consumed := gatheredGauges(t, metrics, "certificate_validity_consumed_ratio", "csr_id")
	if len(consumed) != len(ratios) {
		t.Fatalf("got %d ratio series, want %d", len(consumed), len(ratios))
	}
	for index, expected := range ratios {
		csrID := big.NewInt(int64(index + 1)).String()
		if actual, exists := consumed[csrID]; !exists || math.Abs(actual-expected) > 1e-9 {
			t.Errorf("CSR %s: got %v (present %v), want %v", csrID, actual, exists, expected)
		}
	}
	for _, name := range []string{"certificate_not_before_timestamp_seconds", "certificate_not_after_timestamp_seconds"} {
		values := gatheredGauges(t, metrics, name, "csr_id")
		if len(values) != 9 {
			t.Errorf("%s: got %d series, want 9", name, len(values))
		}
		expected := float64(now.Add(-650 * time.Second).Unix())
		if name == "certificate_not_after_timestamp_seconds" {
			expected += 1000
		}
		if actual, exists := values["2"]; !exists || actual != expected {
			t.Errorf("%s CSR 2: got %v, want %v", name, actual, expected)
		}
	}
	requests[0].Status = "Revoked"
	requests[1].Status = "Rejected"
	metrics.generateCertificateMetrics(requests[:2], now)
	for _, name := range []string{"certificate_not_before_timestamp_seconds", "certificate_not_after_timestamp_seconds", "certificate_validity_consumed_ratio"} {
		if values := gatheredGauges(t, metrics, name, "csr_id"); len(values) != 0 {
			t.Errorf("stale %s series: %v", name, values)
		}
	}
	for label, value := range gatheredGauges(t, metrics, "certificates_validity_consumed", "threshold") {
		if value != 0 {
			t.Errorf("stale threshold %s count: %v", label, value)
		}
	}
}
