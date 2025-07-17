package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

func TestStatus(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()

	t.Run("status not initialized", func(t *testing.T) {
		statusCode, statusResponse, err := getStatus(ts.URL, client, "")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		if statusResponse.Error != "" {
			t.Fatalf("expected error %q, got %q", "", statusResponse.Error)
		}

		if statusResponse.Result.Initialized {
			t.Fatalf("expected initialized to be false")
		}

		if statusResponse.Result.Version == "" {
			t.Fatalf("expected version to be set")
		}
	})
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	t.Run("status initialized", func(t *testing.T) {
		statusCode, statusResponse, err := getStatus(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		if statusResponse.Error != "" {
			t.Fatalf("expected error %q, got %q", "", statusResponse.Error)
		}

		if !statusResponse.Result.Initialized {
			t.Fatalf("expected initialized to be true")
		}

		if statusResponse.Result.Version == "" {
			t.Fatalf("expected version to be set")
		}
	})
}

type GetStatusResponseResult struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
}

type GetStatusResponse struct {
	Error  string                  `json:"error,omitempty"`
	Result GetStatusResponseResult `json:"result"`
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
	defer res.Body.Close()
	var statusResponse GetStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&statusResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &statusResponse, nil
}
