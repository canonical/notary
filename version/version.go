package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var version string

func GetVersion() string {
	return strings.TrimSpace(version)
}
