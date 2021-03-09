package tracing

import (
	"fmt"

	propjaeger "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/trace/jaeger"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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
) (tp trace.TracerProvider, closer func(), err error) {
	endpointOption := jaeger.WithAgentEndpoint(endpoint)
	if endpointType == EndpointTypeCollector {
		endpointOption = jaeger.WithCollectorEndpoint(endpoint)
	}

	tp, closer, err = jaeger.NewExportPipeline(
		endpointOption,
		jaeger.WithProcess(jaeger.Process{
			ServiceName: serviceName,
		}),
		jaeger.WithSDK(&sdktrace.Config{DefaultSampler: sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingFraction))}),
		jaeger.WithDisabled(endpoint == ""),
	)
	if err != nil {
		return tp, closer, fmt.Errorf("create jaeger export pipeline: %w", err)
	}

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propjaeger.Jaeger{},
		propagation.Baggage{},
	))

	return tp, closer, nil
}
