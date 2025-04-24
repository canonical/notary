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

	zapConfig.OutputPaths = []string{opts.System.Output}
	zapConfig.Level.SetLevel(logLevel)
	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger.Sugar(), nil
}
