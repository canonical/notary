package server

import "testing"

func TestACMENotLeaderMessage(t *testing.T) {
	got := acmeNotLeaderMessage("10.0.0.1:9000")
	want := "ACME signing is only available on the cluster leader (10.0.0.1:9000)"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if acmeNotLeaderMessage("") != "ACME signing is only available on the cluster leader" {
		t.Fatalf("empty address: %q", acmeNotLeaderMessage(""))
	}
}
