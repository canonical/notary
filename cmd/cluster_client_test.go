package cmd

import (
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/server"
)

// external_hostname is documented as accepting an optional port, so the
// configured port must not be appended a second time.
func TestAPIHostPort(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     int
		want     string
	}{
		{"bare hostname", "notary.example.com", 3000, "notary.example.com:3000"},
		{"hostname already carrying a port", "notary.example.com:2111", 3000, "notary.example.com:2111"},
		{"unset", "", 3000, "localhost:3000"},
		{"IPv4", "10.0.0.1", 3000, "10.0.0.1:3000"},
		{"IPv6", "::1", 3000, "[::1]:3000"},
		{"IPv6 already carrying a port", "[2001:db8::1]:2111", 3000, "[2001:db8::1]:2111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := apiHostPort(&config.AppConfig{ExternalHostname: tt.hostname, Port: tt.port})
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The address is printed for an operator to run on a different machine, so a
// loopback one is worse than none: it would send the new node to itself.
func TestAdvertisedAddress(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		want     string
	}{
		{"routable hostname", "notary.example.com:3000", "notary.example.com:3000"},
		{"routable address", "10.0.0.1:3000", "10.0.0.1:3000"},
		{"localhost", "localhost:3000", ""},
		{"localhost cased", "LocalHost:3000", ""},
		{"loopback IPv4", "127.0.0.1:3000", ""},
		{"loopback IPv6", "[::1]:3000", ""},
		{"unspecified", "0.0.0.0:3000", ""},
		{"no port at all", "notary.example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := advertisedAddress(tt.hostPort); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClusterMemberRoles(t *testing.T) {
	tests := []struct {
		member server.ClusterMemberResponse
		want   string
	}{
		{server.ClusterMemberResponse{Role: "voter", Leader: true}, "database-leader"},
		{server.ClusterMemberResponse{Role: "voter"}, "database-voter"},
		{server.ClusterMemberResponse{Role: "standby"}, "database-standby"},
		{server.ClusterMemberResponse{Role: "spare"}, "spare"},
	}
	for _, tt := range tests {
		if got := clusterMemberRoles(tt.member); got != tt.want {
			t.Errorf("role %q leader %t: got %q, want %q", tt.member.Role, tt.member.Leader, got, tt.want)
		}
	}
}
