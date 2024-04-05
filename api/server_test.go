package server_test

import (
	"testing"

	server "github.com/canonical/gocert/api"
)

func TestNewServerSuccess(t *testing.T) {
	testCases := []struct {
		desc string
		cert string
		key  string
	}{
		{
			desc: "Correct certificate and key",
			cert: "Should be a valid cert",
			key:  "Should be a valid key",
		},
		{
			desc: "Empty certificate",
			cert: "",
			key:  "Should be a valid key",
		},
		{
			desc: "Empty key",
			cert: "Should be a valid cert",
			key:  "",
		},
		{
			desc: "Empty certificate and key",
			cert: "",
			key:  "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			s, err := server.NewServer(tC.cert, tC.key)
			if err != nil {
				t.Errorf("Error occured: %s", err)
			}
			if s.TLSConfig.Certificates == nil {
				t.Errorf("No certificates were configured for server")
			}
		})
	}
}

func TestNewServerFail(t *testing.T) {
	testCases := []struct {
		desc string
		cert string
		key  string
	}{
		{
			desc: "Wrong certificate",
			cert: "Should be invalid",
			key:  "Should be valid",
		},
		{
			desc: "Wrong key",
			cert: "Should be valid",
			key:  "Should be invalid",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := server.NewServer(tC.cert, tC.key)
			if err != nil {
				t.Errorf("Expected error")
			}
		})
	}
}
