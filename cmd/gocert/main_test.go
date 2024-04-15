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
	invalidYAMLConfig = `wrong: fields
every: where`
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
		ExpectedExit   int
		ExpectedOutput string
	}{
		{"flags not set", []string{}, 1, "Providing a valid config file is required."},
		{"config file not valid", []string{"-config", "config_invalid.yaml"}, 1, "Config file validation failed:"},
		{"database not connectable", []string{"-config", "config_invalid_db.yaml"}, 1, "Couldn't connect to database:"},
		{"server couldn't be created", []string{"-config", "config_invalid.yaml"}, 1, "Couldn't create server:"},
	}
	for _, tc := range cases {
		flag.CommandLine = flag.NewFlagSet(tc.Name, flag.ExitOnError)
		os.Args = append([]string{tc.Name}, tc.Args...)
		// main()
	}
}
