// Contains helper functions for testing the server
package server_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func prepareUserAccounts(url string, client *http.Client, adminToken, nonAdminToken *string) func(*testing.T) {
	return func(t *testing.T) {
		req, err := http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(adminUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("creating the first request should succeed when unauthorized. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(validUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the second request should have been rejected. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/login", strings.NewReader(adminUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resBody, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("the admin login request should have succeeded. status code received: %d", res.StatusCode)
		}
		*adminToken = string(resBody)
		req, err = http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(validUser))
		req.Header.Set("Authorization", "Bearer "+*adminToken)
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("creating the second request should have succeeded when given the admin auth header. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/login", strings.NewReader(validUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resBody, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("the admin login request should have succeeded. status code received: %d", res.StatusCode)
		}
		*nonAdminToken = string(resBody)
	}
}
