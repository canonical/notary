package logger

import (
	"github.com/canonical/notary/internal/config"
	"go.uber.org/zap"
)

var (
	Logger *zap.Logger
)

func NewLogger(opts *config.Logging) (*zap.SugaredLogger, error) {
	zapConfig := zap.NewProductionConfig()
	zapConfig.Level.SetLevel(zap.DebugLevel)

	if opts.System.Output == "stdout" {
		zapConfig.OutputPaths = []string{"stdout"}
	}
	if opts.System.Output == "file" {
		zapConfig.OutputPaths = []string{opts.System.Path}
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	Logger = logger
	return logger.Sugar(), nil
}
