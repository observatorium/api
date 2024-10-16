package tracing

import (
	"context"
	"fmt"

	propjaeger "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.5.0"
	"go.opentelemetry.io/otel/trace/noop"
)

// InitTracer creates an OTel TracerProvider that exports the traces to a Jaeger agent/collector.
func InitTracer(
	serviceName string,
	endpoint string,
	samplingFraction float64,
) (err error) {
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return nil
	}

	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return fmt.Errorf("failed to create otlp exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingFraction))),
		sdktrace.WithBatcher(exporter),
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
