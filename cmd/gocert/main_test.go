package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	validCert = `-----BEGIN CERTIFICATE-----
MIIELjCCAxagAwIBAgICBnowDQYJKoZIhvcNAQELBQAwJzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD0Nhbm9uaWNhbCwgSU5DLjAeFw0yNDA0MDUxMDAzMjhaFw0zNDA0
MDUxMDAzMjhaMCcxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9DYW5vbmljYWwsIElO
Qy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDAP98jcfNw40HbS1xR
6UpSQTp4AGldFWQZBOFaVzD+eh7sYM/BFdT0dZRHGjXxL77ewDbwdwAFJ5zuxo+u
8/VgKGRpK6KCnKailmVrdRDhA45airMRQN6QXurN4NZgXcCHJWGAQKA9XJzcwGJF
l5LxoFY58wCv0d1JP8fgmbcgIRQTCIvhrlgrJ5Acz9QP6BuaxEHKbYYvWyTWtAhi
HS/w51yEbh6959ceJGBDZPyEVd9sfGipvHrA73+33+XBluRcUuWV4dCecyP/m+8C
jTBmW5s8gS6JUDE8yl99qm7CnXTkNDqPXThrorcKRwcHrw3ZEOm5rUPLuyzGBx/C
DZUbY9bsvHJMHOHlbwiY+M2MFIO+3H6qyfPfcHs8NFkrZh/as+9hrEzSYcz+tGBi
NynkSmNPQi4yzT00ilKYgcBhPdDDlBbdhcmdeFA3XE880VkQdJgefsYpCgYRdILm
DDd6ZMfZsQOJjuRC8rQKLO+z1X5JhiOlkNxZaOkq9b9eu7230rxTFCGocn0l9oKw
0q8OIDOTb7UKdIaGq/y++uRxe0hhNoijN1OJvh+R3/KGuztu5Y8ejksIxKBrUqCg
bUDXmQ82xbdJ36qF+NHBqFqFaKhH1XuK6eAIfqgQam/u9HNZZw3mOdm9rvIZfwIT
F9gvSwm1bxzyIHL/zWOgyfzckQIDAQABo2QwYjAOBgNVHQ8BAf8EBAMCB4AwHQYD
VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDgQHBAUBAgMEBjAhBgNV
HREEGjAYhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IB
AQB4UEu1/vTpEuuwoqgFpp8tEMewwBQ/CXPBN5seDnd/SUMXFrxk58f498qI3FQy
q98a+89jPWRGA5LY+DfIS82NYCwbKuvTzuJRoUpMPbebrhu7OQl7qQT6n8VOCy6x
IaRnPI0zEGbg2v340jMbB26FiyaFKyHEc24nnq3suZFmbslXzRE2Ebut+Qtft8he
0pSNQXtz5ULt0c8DTje7j+mRABzus45cj3HMDO4vcVRrHegdTE8YcZjwAFTKxqpg
W7GwJ5qPjnm6EMe8da55m8Q0hZchwGZreXNG7iCaw98pACBNgOOxh4LOhEZy25Bv
ayrvWnmPfg1u47sduuhHeUid
-----END CERTIFICATE-----`
	validPK = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	validConfig = `key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
db)path: "./certs.db"
port: 8000
pebble_notices: false`
	invalidConfig = `hello: "world"
goodbye: "world"`
	invalidDBConfig = `key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
db_path: "/etc/hosts"
port: 8000
pebble_notices: false`
)

func TestMain(m *testing.M) {
	cmd := exec.Command("go", "install", "./...")
	if err := cmd.Run(); err != nil {
		log.Fatalf("couldn't install the gocert CLI")
	}

	testfolder, err := os.MkdirTemp("./", "configtest-")
	if err != nil {
		log.Fatalf("couldn't create temp directory")
	}
	writeCertErr := os.WriteFile(testfolder+"/cert_test.pem", []byte(validCert), 0644)
	writeKeyErr := os.WriteFile(testfolder+"/key_test.pem", []byte(validPK), 0644)
	if writeCertErr != nil || writeKeyErr != nil {
		log.Fatalf("couldn't create temp testing file")
	}
	if err := os.Chdir(testfolder); err != nil {
		log.Fatalf("couldn't enter testing directory")
	}

	exitval := m.Run()

	if err := os.Chdir("../"); err != nil {
		log.Fatalf("couldn't change back to parent directory")
	}
	if err := os.RemoveAll(testfolder); err != nil {
		log.Fatalf("couldn't remove temp testing directory")
	}
	os.Exit(exitval)
}

func TestGoCertFail(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	cases := []struct {
		Name           string
		Args           []string
		ConfigYAML     string
		ExpectedOutput string
	}{
		{"flags not set", []string{}, validConfig, "Providing a valid config file is required."},
		{"config file not valid", []string{"-config", "config.yaml"}, invalidConfig, "config file validation failed:"},
		{"database not connectable", []string{"-config", "config.yaml"}, invalidDBConfig, "Couldn't connect to database:"},
	}
	for _, tc := range cases {
		writeConfigErr := os.WriteFile("config.yaml", []byte(tc.ConfigYAML), 0644)
		if writeConfigErr != nil {
			t.Errorf("Failed writing config file")
		}
		flag.CommandLine = flag.NewFlagSet(tc.Name, flag.ExitOnError)
		cmd := exec.Command("gocert", tc.Args...)
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			t.Errorf("Failed running command")
		}

		slurp, _ := io.ReadAll(stderr)

		if err := cmd.Wait(); err == nil {
			t.Errorf("Command did not fail")
		}
		if !strings.Contains(string(slurp), tc.ExpectedOutput) {
			t.Errorf("%s: Expected error not found: %s", tc.Name, slurp)
		}
	}
}
