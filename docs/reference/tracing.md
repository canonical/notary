# Distributed Tracing in Notary

Notary supports distributed tracing using OpenTelemetry, which allows you to monitor and troubleshoot request flows across the service. Traces can be viewed in any compatible visualization tool, such as Grafana Tempo.

## Configuration

To enable tracing in Notary, add the following configuration to your YAML configuration file:

```yaml
tracing:
  service_name: "notary"  # Optional, defaults to "notary"
  endpoint: "tempo:4317" # Required if enabled, the OpenTelemetry gRPC endpoint
  sampling_rate: "100%"   # Optional, defaults to 100% (1.0)
```

### Configuration Options

- **service_name**: The name that will identify your service in the tracing system
- **endpoint**: The URL of your Tempo (or other OpenTelemetry collector) endpoint
- **sampling_rate**: The percentage of traces to sample. Can be specified as:
  - A percentage (e.g., "10%", "50%", "100%")
  - A decimal value between 0.0 and 1.0 (e.g., "0.1", "0.5", "1.0")

## Viewing Traces

Traces are sent to the configured Tempo URL, where they can be visualized using Grafana or any other compatible tool.

### Example Tempo Configuration with Docker Compose

Here's a minimal example of how to set up Tempo with Docker Compose:

```yaml
version: '3'
services:
  tempo:
    image: grafana/tempo:latest
    command: [ "-config.file=/etc/tempo.yaml" ]
    volumes:
      - ./tempo.yaml:/etc/tempo.yaml
    ports:
      - "3200:3200"  # Tempo server
      - "4317:4317"  # OTLP gRPC

  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./grafana-datasources.yaml:/etc/grafana/provisioning/datasources/datasources.yaml
    ports:
      - "3000:3000"
    depends_on:
      - tempo
```

### trace flow

Notary's tracing implementation tracks HTTP requests through the system, including:

- HTTP method and path
- Response status codes
- Error information
- Duration of requests

## Troubleshooting

If traces are not appearing in your visualization tool:

1. Verify that tracing is enabled in your configuration
2. Check that the `endpoint` is correct and accessible from your Notary instance
3. Examine the Notary logs for any errors related to tracing
4. Ensure that your sampling rate is high enough to capture traces (set to "100%" for testing)

## Performance Considerations

Tracing adds a small overhead to request processing. In production environments, consider:

- Using a lower sampling rate (e.g., "10%") to reduce overhead
- Monitoring the impact on service response times
- Adjusting batch settings if handling very high volumes

## Extending Tracing

For developers extending Notary, you can add custom spans to functions by accessing the tracer:

```go
// Example of adding a custom span
func myFunction(ctx context.Context) {
    tracer := otel.Tracer("github.com/canonical/notary")
    ctx, span := tracer.Start(ctx, "myFunction")
    defer span.End()

    // Add attributes to the span
    span.SetAttributes(attribute.String("key", "value"))

    // Your function code here
}
```
