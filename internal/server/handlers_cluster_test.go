package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestListClusterMembers(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	req, err := http.NewRequest("GET", ts.URL+"/api/v1/cluster", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", res.StatusCode, http.StatusOK)
	}

	var body struct {
		Data []struct {
			Name    string `json:"name"`
			ID      uint64 `json:"id"`
			Address string `json:"address"`
			Role    string `json:"role"`
			Leader  bool   `json:"leader"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data) != 1 {
		t.Fatalf("got %d members, want 1", len(body.Data))
	}
	m := body.Data[0]
	if m.ID == 0 {
		t.Fatal("expected member id")
	}
	if !strings.HasPrefix(m.Address, "127.0.0.1:") {
		t.Fatalf("unexpected address %q", m.Address)
	}
	if m.Role == "" {
		t.Fatal("expected role")
	}
	if m.Name == "" {
		t.Fatal("expected member name")
	}
	if !m.Leader {
		t.Fatal("expected single-node member to be leader")
	}
}

func TestAddClusterMemberToken(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/cluster/members", strings.NewReader(`{"server_name":"node2"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("got %d, want %d", res.StatusCode, http.StatusCreated)
	}
	var body struct {
		Data struct {
			ServerName string `json:"server_name"`
			JoinToken  string `json:"join_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.ServerName != "node2" || body.Data.JoinToken == "" {
		t.Fatalf("unexpected data %+v", body.Data)
	}

	del, err := http.NewRequest("DELETE", ts.URL+"/api/v1/cluster/members/"+body.Data.ServerName, nil)
	if err != nil {
		t.Fatal(err)
	}
	del.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	delRes, err := client.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer delRes.Body.Close()
	if delRes.StatusCode != http.StatusNotFound && delRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("remove pending name: got %d", delRes.StatusCode)
	}
}
