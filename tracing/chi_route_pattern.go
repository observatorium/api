package tracing

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// WithChiRoutePattern annotates spans and otelhttp metrics using Chi's matched route pattern.
func WithChiRoutePattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		pattern := chi.RouteContext(r.Context()).RoutePattern()
		if pattern == "" {
			return
		}

		// Align with net/http convention used by otelhttp route extraction.
		r.Pattern = r.Method + " " + pattern

		routeAttr := attribute.String("http.route", pattern)
		trace.SpanFromContext(r.Context()).SetAttributes(routeAttr)

		labeler, _ := otelhttp.LabelerFromContext(r.Context())
		labeler.Add(routeAttr)
	})
}
