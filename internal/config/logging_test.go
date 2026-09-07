package config

import "testing"

func TestLoggingSectionDefaultsWhenMissing(t *testing.T) {
	sys := loggingSection(nil, "system")
	if sys.GetString("level") != "debug" {
		t.Fatalf("system level: %q", sys.GetString("level"))
	}
	if sys.GetString("output") != "stdout" {
		t.Fatalf("system output: %q", sys.GetString("output"))
	}
	audit := loggingSection(nil, "audit")
	if audit.GetString("output") != "stdout" {
		t.Fatalf("audit output: %q", audit.GetString("output"))
	}
}

func TestLoggingConfigFromParentDefaults(t *testing.T) {
	got := loggingConfigFrom(nil)
	if got == nil {
		t.Fatal("expected default logging viper")
	}
}
