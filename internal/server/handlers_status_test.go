package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

func TestStatus(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()

	t.Run("status not initialized on fresh server", func(t *testing.T) {
		statusCode, statusResponse, err := getStatus(ts.URL, client, "")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		if statusResponse.Message != "" {
			t.Fatalf("expected message %q, got %q", "", statusResponse.Message)
		}

		if statusResponse.Data.Initialized {
			t.Fatalf("expected initialized to be false on fresh server")
		}

		if statusResponse.Data.Version == "" {
			t.Fatalf("expected version to be set")
		}
	})

	// Create the first admin account (triggers initialization)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	t.Run("status initialized after first user created", func(t *testing.T) {
		statusCode, statusResponse, err := getStatus(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		if statusResponse.Message != "" {
			t.Fatalf("expected message %q, got %q", "", statusResponse.Message)
		}

		if !statusResponse.Data.Initialized {
			t.Fatalf("expected initialized to be true after creating user")
		}

		if statusResponse.Data.Version == "" {
			t.Fatalf("expected version to be set")
		}
	})
}

type GetStatusResponseResult struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
}

type GetStatusResponse struct {
	Message string                  `json:"message,omitempty"`
	Data    GetStatusResponseResult `json:"data"`
}

func getStatus(url string, client *http.Client, adminToken string) (int, *GetStatusResponse, error) {
	req, err := http.NewRequest("GET", url+"/status", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close() // nolint: errcheck
	var statusResponse GetStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&statusResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &statusResponse, nil
}
