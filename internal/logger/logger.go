package logger

import (
	"fmt"

	"github.com/canonical/notary/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(opts *config.Logging) (*zap.SugaredLogger, error) {
	zapConfig := zap.NewProductionConfig()

	logLevel, err := zapcore.ParseLevel(string(opts.System.Level))
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	zapConfig.Level.SetLevel(logLevel)

	switch opts.System.Output {
	case config.Stdout:
		zapConfig.OutputPaths = []string{"stdout"}
	case config.File:
		zapConfig.OutputPaths = []string{opts.System.Path}
	default:
		return nil, fmt.Errorf("invalid log output: %s", opts.System.Output)
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger.Sugar(), nil
}
