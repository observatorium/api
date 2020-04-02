package server

import (
	"context"
	"net/http"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
	"github.com/observatorium/observatorium/prober"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const DefaultGracePeriod = 5 * time.Second
const DefaultTimeout = 5 * time.Minute

// Server TODO
type Server struct {
	logger log.Logger
	prober *prober.Prober
	srv    *http.Server

	opts options
}

// New creates a new Server
func New(logger log.Logger, reg *prometheus.Registry, opts ...Option) Server {
	options := options{
		gracePeriod: DefaultGracePeriod,
		profile:     false,
	}

	for _, o := range opts {
		o.apply(&options)
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(options.timeout))

	if options.profile {
		r.Mount("/debug", middleware.Profiler())
	}

	ins := newInstrumentationMiddleware(reg)
	p := prober.New(logger)

	registerProber(r, p)

	uiPath := "/ui/metrics/v1"

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, uiPath+"/graph", http.StatusMovedPermanently)
	})

	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})).ServeHTTP(w, r)
	})

	if options.metricsUIEndpoint != nil {
		r.Get(uiPath+"/*",
			ins.newHandler("ui", proxy.New(logger, uiPath, options.metricsUIEndpoint, options.proxyOptions...)))
	}

	namespace := "/api/metrics/v1"
	r.Route(namespace, func(r chi.Router) {
		if options.metricsReadEndpoint != nil {
			r.Get("/api/v1/query",
				ins.newHandler("query", proxy.New(logger, namespace+"/api/v1", options.metricsReadEndpoint, options.proxyOptions...)))

			r.Get("/api/v1/query_range",
				ins.newHandler("query_range", proxy.New(logger, namespace+"/api/v1", options.metricsReadEndpoint, options.proxyOptions...)))

			r.Get("/api/v1/*",
				ins.newHandler("read", proxy.New(logger, namespace+"/api/v1", options.metricsReadEndpoint, options.proxyOptions...)))
		}

		writePath := "/write"
		r.Post(writePath,
			ins.newHandler("write", proxy.New(logger, namespace+writePath, options.metricsWriteEndpoint, options.proxyOptions...)))
	})

	// NOTICE: Following redirects added to be compatible with existing Read UI.
	// Paths are explicitly specified to prevent unnecessary request to read handler.
	r.Get("/graph", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/v1/metrics/graph", http.StatusMovedPermanently)
	})

	r.Get("/stores", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/v1/metrics/stores", http.StatusMovedPermanently)
	})

	r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/v1/metrics/status", http.StatusMovedPermanently)
	})

	p.Healthy()

	return Server{
		logger: logger,
		prober: p,
		srv:    &http.Server{Addr: options.listen, Handler: r},
		opts:   options,
	}
}

// ListenAndServe TODO
func (s *Server) ListenAndServe() error {
	level.Info(s.logger).Log("msg", "starting the HTTP server", "address", s.opts.listen)
	s.prober.Ready()

	return s.srv.ListenAndServe()
}

// Shutdown TODO
func (s *Server) Shutdown(err error) {
	s.prober.NotReady(err)

	if err == http.ErrServerClosed {
		level.Warn(s.logger).Log("msg", "internal server closed unexpectedly")
		return
	}

	ctx, c := context.WithTimeout(context.Background(), s.opts.gracePeriod)
	defer c()

	level.Info(s.logger).Log("msg", "shutting down internal server")

	if err := s.srv.Shutdown(ctx); err != nil {
		level.Error(s.logger).Log("msg", "shutting down failed", "err", err)
	}
}

func registerProber(r *chi.Mux, p *prober.Prober) {
	r.Get("/-/healthy", p.HealthyHandler())
	r.Get("/-/ready", p.ReadyHandler())
}
