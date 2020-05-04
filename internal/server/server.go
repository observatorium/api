package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	metricslegacy "github.com/observatorium/observatorium/internal/api/metrics/legacy"
	metricsv1 "github.com/observatorium/observatorium/internal/api/metrics/v1"
)

// gracePeriod is duration the server gracefully shuts down.
const gracePeriod = 2 * time.Minute

// DefaultRequestTimeout is the default value of the timeout duration per request.
const DefaultRequestTimeout = 2 * time.Minute

// DefaultReadTimeout is the default value of the maximum duration for reading the entire request, including the body.
const DefaultReadTimeout = 2 * time.Minute

// DefaultWriteTimeout is the default value of the maximum duration before timing out writes of the response.
const DefaultWriteTimeout = 2 * time.Minute

// Server defines parameters for running an HTTP server.
type Server struct {
	logger log.Logger
	srv    *http.Server

	opts options
}

// New creates a new Server.
func New(logger log.Logger, reg *prometheus.Registry, opts ...Option) Server {
	options := options{}

	for _, o := range opts {
		o.apply(&options)
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(options.requestTimeout))
	r.Use(Logger(logger))

	ins := NewInstrumentationMiddleware(reg)

	r.Mount("/api/v1",
		metricslegacy.NewHandler(
			options.metricsReadEndpoint,
			metricslegacy.Logger(logger),
			metricslegacy.Registry(reg),
			metricslegacy.HandlerInstrumenter(ins),
		))

	r.Mount("/api/metrics/v1",
		http.StripPrefix("/api/metrics/v1",
			metricsv1.NewHandler(
				options.metricsReadEndpoint,
				options.metricsWriteEndpoint,
				options.metricsUIEndpoint,
				metricsv1.Logger(logger),
				metricsv1.Registry(reg),
				metricsv1.HandlerInstrumenter(ins),
			),
		),
	)

	return Server{
		logger: logger,
		srv: &http.Server{
			Addr:         options.listen,
			Handler:      r,
			TLSConfig:    options.tlsConfig,
			ReadTimeout:  options.readTimeout,
			WriteTimeout: options.writeTimeout,
		},
		opts: options,
	}
}

// Logger returns a middleware to log HTTP requests
func Logger(logger log.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			keyvals := []interface{}{
				"request", middleware.GetReqID(r.Context()),
				"proto", r.Proto,
				"method", r.Method,
				"status", ww.Status(),
				"content", r.Header.Get("Content-Type"),
				"path", r.URL.Path,
				"duration", time.Since(start),
				"bytes", ww.BytesWritten(),
			}

			if ww.Status()/100 == 5 {
				level.Warn(logger).Log(keyvals...)
				return
			}
			level.Debug(logger).Log(keyvals...)
		})
	}
}

// ListenAndServe listens on the TCP network address and handles connections with given server configuration.
func (s *Server) ListenAndServe() error {
	level.Info(s.logger).Log("msg", "starting the HTTP server", "address", s.opts.listen)

	if s.opts.tlsConfig != nil {
		// certFile and keyFile passed in TLSConfig at initialization.
		return s.srv.ListenAndServeTLS("", "")
	}

	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(err error) {
	if err == http.ErrServerClosed {
		level.Warn(s.logger).Log("msg", "internal server closed unexpectedly")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
	defer cancel()

	level.Info(s.logger).Log("msg", "shutting down internal server")

	if err := s.srv.Shutdown(ctx); err != nil {
		level.Error(s.logger).Log("msg", "shutting down failed", "err", err)
	}
}
