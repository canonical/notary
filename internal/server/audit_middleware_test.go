package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Helper to build a router with an observed audit logger
// Use testutils helper for observed server, keep function name for local tests
// Deprecated local helper; kept for compatibility in this file.
func newObservedRouter(t *testing.T) *observer.ObservedLogs { t.Helper(); _, logs := tu.MustPrepareServer(t); return logs }

func findStringField(entry observer.LoggedEntry, key string) string {
    for _, f := range entry.Context {
        if f.Key == key {
            switch f.Type {
            case zapcore.StringType:
                return f.String
            }
        }
    }
    return ""
}

func TestAuditMiddleware_LogsFailureAndReason(t *testing.T) {
    ts, logs := tu.MustPrepareServer(t)
    // Clear any initialization noise
    _ = logs.TakeAll()

    // Unauthorized GET (no token)
    req, err := http.NewRequest("GET", ts.URL+"/api/v1/certificate_requests", nil)
    if err != nil {
        t.Fatalf("new request: %v", err)
    }
    res, err := ts.Client().Do(req)
    if err != nil {
        t.Fatalf("do request: %v", err)
    }
    if res.StatusCode != http.StatusUnauthorized {
        t.Fatalf("expected %d, got %d", http.StatusUnauthorized, res.StatusCode)
    }

    entries := logs.TakeAll()
    var haveAuthzFail, haveAPIFailed bool
    for _, e := range entries {
        if e.LoggerName != "audit" {
            continue
        }
        switch findStringField(e, "event") {
        case "authz_fail":
            haveAuthzFail = true
        case "api_action":
            if findStringField(e, "action") == "GET certificate_requests (failed)" {
                haveAPIFailed = true
            }
        }
    }
    if !haveAuthzFail {
        t.Fatalf("expected UnauthorizedAccess audit entry (event=authz_fail)")
    }
    if !haveAPIFailed {
        t.Fatalf("expected APIAction failure audit entry for GET certificate_requests")
    }
}

func TestAuditMiddleware_LogsSuccessfulRead(t *testing.T) {
    ts, logs := tu.MustPrepareServer(t)

    // Create first user (open route: first user doesn't require token)
    createBody := map[string]any{
        "email":    "admin@example.com",
        "password": "Admin123",
        "role_id":  0,
    }
    payload, _ := json.Marshal(createBody)
    req, err := http.NewRequest("POST", ts.URL+"/api/v1/accounts", bytes.NewReader(payload))
    if err != nil {
        t.Fatalf("new request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")
    res, err := ts.Client().Do(req)
    if err != nil {
        t.Fatalf("do request: %v", err)
    }
    if res.StatusCode != http.StatusCreated {
        t.Fatalf("expected %d, got %d", http.StatusCreated, res.StatusCode)
    }

    // Login to obtain JWT
    loginBody := map[string]any{
        "email":    "admin@example.com",
        "password": "Admin123",
    }
    loginPayload, _ := json.Marshal(loginBody)
    req, err = http.NewRequest("POST", ts.URL+"/login", bytes.NewReader(loginPayload))
    if err != nil {
        t.Fatalf("new request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")
    res, err = ts.Client().Do(req)
    if err != nil {
        t.Fatalf("do request: %v", err)
    }
    if res.StatusCode != http.StatusOK {
        t.Fatalf("expected %d, got %d", http.StatusOK, res.StatusCode)
    }
    var loginResp struct {
        Result struct{ Token string `json:"token"` }
    }
    if err := json.NewDecoder(res.Body).Decode(&loginResp); err != nil {
        t.Fatalf("decode login response: %v", err)
    }

    // Clear logs so we only capture the read success
    _ = logs.TakeAll()

    // Authenticated GET (should log api_action success)
    req, err = http.NewRequest("GET", ts.URL+"/api/v1/certificate_requests", nil)
    if err != nil {
        t.Fatalf("new request: %v", err)
    }
    req.Header.Set("Authorization", "Bearer "+loginResp.Result.Token)
    res, err = ts.Client().Do(req)
    if err != nil {
        t.Fatalf("do request: %v", err)
    }
    if res.StatusCode != http.StatusOK {
        t.Fatalf("expected %d, got %d", http.StatusOK, res.StatusCode)
    }

    entries := logs.TakeAll()
    var haveAPISuccess bool
    for _, e := range entries {
        if e.LoggerName != "audit" {
            continue
        }
        if findStringField(e, "event") == "api_action" && findStringField(e, "action") == "GET certificate_requests" {
            haveAPISuccess = true
            break
        }
    }
    if !haveAPISuccess {
        t.Fatalf("expected APIAction success audit entry for GET certificate_requests")
    }
}


