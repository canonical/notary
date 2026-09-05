package version

import (
	"strings"
	"testing"
)

func TestGetVersionHasNoNewline(t *testing.T) {
	v := GetVersion()
	if v == "" {
		t.Fatal("expected version")
	}
	if strings.ContainsAny(v, "\r\n") {
		t.Fatalf("version contains whitespace newline: %q", v)
	}
}
