package internal

import (
	"fmt"

	"go.opentelemetry.io/otel/api/core"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/exporter/trace/jaeger"
	"go.opentelemetry.io/otel/exporter/trace/stdout"
	export "go.opentelemetry.io/otel/sdk/export/trace"
	sdk "go.opentelemetry.io/otel/sdk/trace"
)

const (
	// ExporterJaeger TODO
	ExporterJaeger = "jaeger"
	// ExporterStdout TODO
	ExporterStdout = "stdout"
)

// Tracer TODO
type Tracer struct {
	Provider *sdk.Provider
	closer   func()
}

// NewTracer TODO
func NewTracer(exporterName, endpoint string, probability float64) *Tracer {
	var (
		exporter export.SpanSyncer
		err      error
		closer   func()
	)

	switch exporterName {
	case ExporterJaeger:
		var jaegerExporter *jaeger.Exporter
		jaegerExporter, err = jaeger.NewExporter(
			jaeger.WithCollectorEndpoint(endpoint),
			jaeger.WithProcess(jaeger.Process{
				ServiceName: "observatorium",
				Tags: []core.KeyValue{
					key.String("exporter", "jaeger"),
				},
			}),
		)
		closer = func() { jaegerExporter.Flush() }
		exporter = jaegerExporter
	case ExporterStdout:
		exporter, err = stdout.NewExporter(stdout.Options{PrettyPrint: true})
	default:
		panic("unexpected trace exporter")
	}

	if err != nil {
		panic(fmt.Errorf("initialize %s exporter: %w", exporterName, err))
	}

	tp, err := sdk.NewProvider(
		sdk.WithConfig(sdk.Config{DefaultSampler: sdk.ProbabilitySampler(probability)}),
		sdk.WithSyncer(exporter),
	)

	if err != nil {
		panic(fmt.Errorf("initialize tracer: %w", err))
	}

	return &Tracer{
		tp,
		closer,
	}
}

// Close TODO
func (t *Tracer) Close() {
	t.closer()
}
