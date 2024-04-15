package main

import (
	"flag"
	"os"
	"testing"
)

const (
	validConfig = `keypath:  "./key_test.pem"
certpath: "./cert_test.pem"
dbpath: "./certs.db"
port: 8000`
	invalidCertConfig = `keypath:  "./key_test.pem"
certpath: "./wrong_cert_test.pem"
dbpath: "./certs.db"
port: 8000`

	invalidDBConfig = `keypath:  "./nokeyfile.pem"
certpath: "./nocertfile.pem"
dbpath: "/etc/hosts"
port: 8000`
	invalidFileConfig = `keypath:  "./nokeyfile.pem"
certpath: "./nocertfile.pem"
dbpath: "./certs.db"
port: 8000`
)

func TestGoCertFail(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	cases := []struct {
		Name           string
		Args           []string
		ConfigYAML     string
		ExpectedExit   int
		ExpectedOutput string
	}{
		{"flags not set", []string{}, validConfig, 1, "Providing a valid config file is required."},
		{"config file not valid", []string{"-config", "config_invalid.yaml"}, invalidFileConfig, 1, "Config file validation failed:"},
		{"database not connectable", []string{"-config", "config_invalid_db.yaml"}, invalidDBConfig, 1, "Couldn't connect to database:"},
		{"server couldn't be created", []string{"-config", "config_invalid.yaml"}, invalidCertConfig, 1, "Couldn't create server:"},
	}
	for _, tc := range cases {
		flag.CommandLine = flag.NewFlagSet(tc.Name, flag.ExitOnError)
		os.Args = append([]string{tc.Name}, tc.Args...)
		// main()
	}
}
