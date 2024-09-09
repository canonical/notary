package cli

import (
	"flag"
	"fmt"
	"log"

	server "github.com/canonical/notary/internal/api"
	"github.com/canonical/notary/internal/config"
)

type StartCommand struct {
	fs         *flag.FlagSet
	configPath string
}

func (startCommand *StartCommand) Name() string {
	return startCommand.fs.Name()
}

func (startCommand *StartCommand) Init(args []string) error {
	return startCommand.fs.Parse(args)
}

func (startCommand *StartCommand) Run() error {
	if startCommand.configPath == "" {
		return fmt.Errorf("providing a config file is required")
	}
	conf, err := config.Validate(startCommand.configPath)
	if err != nil {
		return fmt.Errorf("couldn't validate config file: %s", err)
	}
	srv, err := server.NewServer(conf.Port, conf.Cert, conf.Key, conf.DBPath, conf.PebbleNotificationsEnabled)
	if err != nil {
		return fmt.Errorf("couldn't create server: %s", err)
	}
	log.Printf("Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("server ran into error: %s", err)
	}
	return nil
}

func NewStartCommand() *StartCommand {
	command := &StartCommand{
		fs: flag.NewFlagSet("start", flag.ContinueOnError),
	}

	command.fs.StringVar(&command.configPath, "config", "", "The config file to be provided to the server")

	return command
}
