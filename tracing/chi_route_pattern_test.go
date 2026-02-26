package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestWithChiRoutePattern(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
	})

	r := chi.NewRouter()
	r.Use(WithChiRoutePattern)
	r.Get("/api/test/{tenant}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ctx, span := tp.Tracer("test").Start(context.Background(), "request")
	labeler := &otelhttp.Labeler{}
	ctx = otelhttp.ContextWithLabeler(ctx, labeler)

	req := httptest.NewRequest(http.MethodGet, "/api/test/acme", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	span.End()

	if w.Code != http.StatusNoContent {
		t.Fatalf("unexpected status code: got %d, want %d", w.Code, http.StatusNoContent)
	}

	attr := attribute.String("http.route", "/api/test/{tenant}")

	if !slices.Contains(labeler.Get(), attr) {
		t.Fatalf("expected labeler to contain %q route attribute", attr.Value.AsString())
	}

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("unexpected ended spans count: got %d, want 1", len(ended))
	}

	if !slices.Contains(ended[0].Attributes(), attr) {
		t.Fatalf("expected span to contain %q route attribute", attr.Value.AsString())
	}
}
