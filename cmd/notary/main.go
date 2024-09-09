package main

import (
	"log"
	"os"

	"github.com/canonical/notary/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		log.Fatalf("Error: %s", err)
	}
}
