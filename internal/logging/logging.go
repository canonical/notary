package logging

import (
	"log"
	"os"
)

var Logger *log.Logger

func init() {
	Logger = log.New(os.Stderr, "", log.LstdFlags)
}
