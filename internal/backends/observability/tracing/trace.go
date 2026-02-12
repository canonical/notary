package tracing

import (
	"context"
	"fmt"
	"time"

	"github.com/canonical/notary/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

// TracerShutdownFunc is a function that can be called to clean up tracing resources.
type TracerShutdownFunc func(context.Context) error

// SetupTracing initializes OpenTelemetry tracing with configuration from the app config
func SetupTracing(ctx context.Context, endpoint string, serviceName string, samplingRate float64, logger *zap.Logger) (TracerShutdownFunc, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("tracing is enabled but endpoint is not configured")
	}

	logger.Info("Setting up tracing",
		zap.String("service_name", serviceName),
		zap.String("endpoint", endpoint),
		zap.Float64("sampling_rate", samplingRate))

	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(), // TODO: support TLS
	)
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version.GetVersion()),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(samplingRate)),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	logger.Info("Tracing has been successfully configured")

	return func(ctx context.Context) error {
		logger.Info("Shutting down tracer provider")
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
		return nil
	}, nil
}
