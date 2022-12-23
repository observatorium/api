package tracing

import (
	"fmt"
	"net"

	propjaeger "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.5.0"
	"go.opentelemetry.io/otel/trace"
)

// EndpointType represents the type of the tracing endpoint.
type EndpointType string

const (
	EndpointTypeCollector EndpointType = "collector"
	EndpointTypeAgent     EndpointType = "agent"
)

// InitTracer creates an OTel TracerProvider that exports the traces to a Jaeger agent/collector.
func InitTracer(
	serviceName string,
	endpoint string,
	endpointType EndpointType,
	samplingFraction float64,
) (err error) {
	if endpoint == "" {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		return nil
	}

	endpointOption := jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint))

	if endpointType == EndpointTypeAgent {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return fmt.Errorf("initializing tracer failed for agent endpoint type: %w", err)
		}

		endpointOption = jaeger.WithAgentEndpoint(
			jaeger.WithAgentHost(host),
			jaeger.WithAgentPort(port),
		)
	}

	exp, err := jaeger.New(endpointOption)
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingFraction))),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(serviceName),
			)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propjaeger.Jaeger{},
		propagation.Baggage{},
	))

	return nil
}
