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

// InitTracer creates an OTel TracerProvider that exports the traces to a Jaeger collector.
func InitTracer(serviceName, collectorEndpoint string, samplingFraction float64) (tp trace.TracerProvider, closer func(), err error) {
	disabled := collectorEndpoint == ""

	tp, closer, err = jaeger.NewExportPipeline(
		jaeger.WithCollectorEndpoint(collectorEndpoint),
		jaeger.WithProcess(jaeger.Process{
			ServiceName: serviceName,
		}),
		jaeger.WithSDK(&sdktrace.Config{DefaultSampler: sdktrace.TraceIDRatioBased(samplingFraction)}),
		jaeger.WithDisabled(disabled),
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
