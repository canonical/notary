package trace

import (
	"context"
	"fmt"
	"time"

	"github.com/canonical/notary/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

// ShutdownTracer is a function that can be called to clean up tracing resources.
type ShutdownTracer func(context.Context) error

// SetupTracing initializes OpenTelemetry tracing with configuration from the app config
func SetupTracing(ctx context.Context, cfg *config.Tracing, logger *zap.Logger) (ShutdownTracer, error) {
	if !cfg.Enabled {
		logger.Info("Tracing is disabled")
		return func(context.Context) error { return nil }, nil
	}

	if cfg.TempoURL == "" {
		return nil, fmt.Errorf("tracing is enabled but endpoint is not configured")
	}

	logger.Info("Setting up tracing",
		zap.String("service_name", cfg.ServiceName),
		zap.String("endpoint", cfg.TempoURL),
		zap.Float64("sampling_rate", cfg.SamplingRate))

	// Create OTLP exporter
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(cfg.TempoURL),
		otlptracegrpc.WithInsecure(), // For simplicity, consider adding TLS for production
	)

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion("1.0.0"), // Consider getting this from app version
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Configure trace provider with sampling rate
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SamplingRate)),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
	)

	// Set global trace provider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("Tracing has been successfully configured")

	// Return a function to shutdown the tracer
	return func(ctx context.Context) error {
		logger.Info("Shutting down tracer provider")
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
		return nil
	}, nil
}
