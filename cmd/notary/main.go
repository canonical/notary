package main

import (
	"fmt"
	"os"

	"github.com/canonical/notary/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
