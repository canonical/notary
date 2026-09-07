package cluster_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
)

func TestDecodeJoinToken(t *testing.T) {
	if _, err := cluster.DecodeJoinToken(""); err == nil {
		t.Fatal("expected error")
	}
	payload, err := json.Marshal(cluster.JoinToken{
		ServerName:  "node2",
		Fingerprint: "abc",
		Addresses:   []string{"10.0.0.1:8000"},
		Secret:      "abc",
		ExpiresAt:   time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cluster.DecodeJoinToken(base64.StdEncoding.EncodeToString(payload))
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerName != "node2" || len(got.Addresses) != 1 || got.Secret != "abc" || got.Fingerprint != "abc" {
		t.Fatalf("%+v", got)
	}
}
