package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canonical/notary/internal/autosign"
	internalLog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAutoSignEndToEnd(t *testing.T) {
	// Prepare DB and server manually so we can pass the DB to the engine.
	database := tu.MustPrepareEmptyDB(t)
	core, _ := observer.New(zapcore.InfoLevel)
	auditZap := zap.New(core)
	appCfg := tu.MustCreateTestAppConfig(t)
	appEnv := tu.MustCreateTestAppEnvironment(t, database)
	appEnv.AuditLogger = internalLog.NewAuditLogger(auditZap)

	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatalf("Couldn't get server: %s", err)
	}
	ts := httptest.NewTLSServer(srv.Handler)
	defer ts.Close()

	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// 1. Create a self-signed CA
	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "AutoSign Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	caID := caResp.Data.ID

	// 2. Create an enabled auto-sign policy for the CA
	statusCode, createResp, err := createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(true),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	if createResp.Data.PolicyID == 0 {
		t.Fatal("expected policy ID to be set")
	}

	// 3. Submit a CSR
	csrRequest := tu.CreateCertificateRequestParams{CSR: tu.AppleCSR}
	statusCode, csrResp, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, csrRequest)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	csrID := csrResp.Data.ID

	// 4. Verify CSR has no certificate yet
	statusCode, getResp, err := tu.GetCertificateRequest(ts.URL, client, adminToken, csrID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
	}
	if getResp.Data.CertificateChain != "" {
		t.Fatal("expected empty certificate chain before auto-sign")
	}

	// 5. Run the auto-sign engine synchronously
	logger, _ := zap.NewDevelopment()
	engine := autosign.New(database, logger, appCfg.ExternalHostname)
	engine.ProcessOutstandingCSRs()

	// 6. Verify CSR now has a certificate chain
	statusCode, getResp, err = tu.GetCertificateRequest(ts.URL, client, adminToken, csrID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
	}
	if getResp.Data.CertificateChain == "" {
		t.Fatal("expected certificate chain after auto-sign, got empty")
	}
	if getResp.Data.Status != "Active" {
		t.Fatalf("expected status Active, got %s", getResp.Data.Status)
	}

}

func TestAutoSignEndToEndDisabledPolicy(t *testing.T) {
	// Prepare DB and server manually so we can pass the DB to the engine.
	database := tu.MustPrepareEmptyDB(t)
	core, _ := observer.New(zapcore.InfoLevel)
	auditZap := zap.New(core)
	appCfg := tu.MustCreateTestAppConfig(t)
	appEnv := tu.MustCreateTestAppEnvironment(t, database)
	appEnv.AuditLogger = internalLog.NewAuditLogger(auditZap)

	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatalf("Couldn't get server: %s", err)
	}
	ts := httptest.NewTLSServer(srv.Handler)
	defer ts.Close()

	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// 1. Create a self-signed CA
	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "AutoSign Disabled CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	caID := caResp.Data.ID

	// 2. Create a DISABLED auto-sign policy
	statusCode, _, err = createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(false),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}

	// 3. Submit a CSR
	csrRequest := tu.CreateCertificateRequestParams{CSR: tu.AppleCSR}
	statusCode, csrResp, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, csrRequest)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	csrID := csrResp.Data.ID

	// 4. Run the auto-sign engine synchronously
	logger, _ := zap.NewDevelopment()
	engine := autosign.New(database, logger, appCfg.ExternalHostname)
	engine.ProcessOutstandingCSRs()

	// 5. Verify CSR is still unsigned
	statusCode, getResp, err := tu.GetCertificateRequest(ts.URL, client, adminToken, csrID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
	}
	if getResp.Data.CertificateChain != "" {
		t.Fatal("expected empty certificate chain when policy is disabled")
	}
}
