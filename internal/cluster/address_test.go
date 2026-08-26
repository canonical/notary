package cluster_test

import (
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

func TestParseAdvertiseAddress(t *testing.T) {
	tests := []struct {
		address string
		ok      bool
	}{
		{"10.0.0.1:9000", true},
		{"notary.example.com:9000", true},
		{"[2001:db8::1]:9000", true},
		{"", false},
		{"10.0.0.1", false},
		{"https://10.0.0.1:9000", false},
		{"http://10.0.0.1:9000", false},
		{":9000", false},
		{"10.0.0.1:", false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			err := cluster.ParseAdvertiseAddress(tt.address)
			if tt.ok && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
