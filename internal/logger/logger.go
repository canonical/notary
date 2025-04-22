package logger

import (
	"go.uber.org/zap"
)

var (
	Logger *zap.Logger
)

type SystemLoggerOutputOpts struct {
	Stdout bool
	File   bool
}

type SystemLoggerOpts struct {
	Level  string
	Output SystemLoggerOutputOpts
	Path   string
}

type LoggerOpts struct {
	System SystemLoggerOpts
}

func NewLogger(opts *LoggerOpts) (*zap.SugaredLogger, error) {
	zapConfig := zap.NewProductionConfig()
	zapConfig.Level.SetLevel(zap.DebugLevel)
	// zapConfig.OutputPaths = []string{opts.System.Path}
	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	Logger = logger
	return logger.Sugar(), nil
}
