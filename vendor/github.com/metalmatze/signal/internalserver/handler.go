package internalserver

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"sort"

	"github.com/metalmatze/signal/healthcheck"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler is a http.ServeMux that knows about all endpoints to render a nice index page.
type Handler struct {
	http.ServeMux
	endpoints []endpoint
	name      string
}

// endpoint has a description to a pattern.
type endpoint struct {
	Pattern     string
	Description string
}

// NewHandler creates a new internalserver Handler.
func NewHandler(options ...Option) *Handler {
	h := &Handler{name: "Internal"}

	for _, option := range options {
		option(h)
	}

	h.HandleFunc("/", h.index)

	return h
}

// AddEndpoint wraps HandleFunc for adding http handlers to add a meaningful description to the index page.
func (h *Handler) AddEndpoint(pattern string, description string, handler http.HandlerFunc) {
	h.endpoints = append(h.endpoints, endpoint{
		Pattern:     pattern,
		Description: description,
	})

	// Sort endpoints by pattern after adding a new one, to always show them in the same order.
	sort.Slice(h.endpoints, func(i, j int) bool {
		return h.endpoints[i].Pattern < h.endpoints[j].Pattern
	})

	h.HandleFunc(pattern, handler)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	html := "<html><head><title>Internal</title></head><body>\n"

	for _, e := range h.endpoints {
		html += fmt.Sprintf("<p><a href='%s'>%s - %s</a></p>\n", e.Pattern, e.Pattern, e.Description)
	}
	html += `</body></html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Option is a func that modifies the configuration for the internalserver handler.
type Option func(h *Handler)

// WithName allows to set an application name for the internalserver handler.
func WithName(name string) Option {
	return func(h *Handler) {
		h.name = name
	}
}

// WithHealthchecks adds the healthchecks endpoints /live and /ready to the internalserver.
func WithHealthchecks(healthchecks healthcheck.Handler) Option {
	return func(h *Handler) {
		h.AddEndpoint(
			"/live",
			"Exposes liveness checks",
			healthchecks.LiveEndpoint,
		)
		h.AddEndpoint(
			"/ready",
			"Exposes readiness checks",
			healthchecks.ReadyEndpoint,
		)
	}
}

// WithPrometheusRegistry adds a /metrics endpoint to the internalserver.
func WithPrometheusRegistry(registry *prometheus.Registry) Option {
	return func(h *Handler) {
		h.AddEndpoint(
			"/metrics",
			"Exposes Prometheus metrics",
			promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP,
		)
	}
}

// WithPProf adds all pprof endpoints under /debug to the internalserver.
func WithPProf() Option {
	return func(h *Handler) {
		m := http.NewServeMux()
		m.HandleFunc("/debug/pprof/", pprof.Index)
		m.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		m.HandleFunc("/debug/pprof/profile", pprof.Profile)
		m.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		m.HandleFunc("/debug/pprof/trace", pprof.Trace)
		m.HandleFunc("/debug/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/debug/pprof/", http.StatusMovedPermanently)
		})

		h.AddEndpoint(
			"/debug/",
			"Exposes pprof endpoints to consume via HTTP",
			m.ServeHTTP,
		)
	}
}
