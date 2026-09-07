package config

import "github.com/spf13/viper"

func loggingConfigFrom(cfg *viper.Viper) *viper.Viper {
	if cfg != nil {
		if sub := cfg.Sub("logging"); sub != nil {
			return sub
		}
	}
	v := viper.New()
	v.SetDefault("system.level", "debug")
	v.SetDefault("system.output", "stdout")
	v.SetDefault("audit.output", "stdout")
	return v
}

// loggingSection returns system or audit logger settings, filling stdout/debug
// defaults when the YAML omits the logging block or a subsection.
func loggingSection(logging *viper.Viper, name string) *viper.Viper {
	section := viper.New()
	section.SetDefault("output", "stdout")
	if name == "system" {
		section.SetDefault("level", "debug")
	}
	if logging == nil {
		return section
	}
	if sub := logging.Sub(name); sub != nil {
		if out := sub.GetString("output"); out != "" {
			section.Set("output", out)
		}
		if name == "system" {
			if level := sub.GetString("level"); level != "" {
				section.Set("level", level)
			}
		}
	}
	return section
}
