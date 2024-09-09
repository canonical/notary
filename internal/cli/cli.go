package cli

import (
	"fmt"
	"os"
)

type Runner interface {
	Init([]string) error
	Run() error
	Name() string
}

func getSupportedCommands() []Runner {
	return []Runner{
		NewStartCommand(),
	}
}

func getSupportedCommandNames() []string {
	allowedSubcommands := []string{}
	for _, cmd := range getSupportedCommands() {
		allowedSubcommands = append(allowedSubcommands, cmd.Name())
	}
	return allowedSubcommands
}

func Run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("you must pass a subcommand. Allowed commands: %v", getSupportedCommandNames())
	}

	subcommand := os.Args[1]

	for _, cmd := range getSupportedCommands() {
		if cmd.Name() == subcommand {
			err := cmd.Init(os.Args[2:])
			if err != nil {
				return fmt.Errorf("failed to initialize %s: %w", subcommand, err)
			}
			return cmd.Run()
		}
	}
	return fmt.Errorf("unknown subcommand: %s. Allowed commands: %v", subcommand, getSupportedCommandNames())
}
