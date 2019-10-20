package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/observatorium/observatorium/internal"
	"github.com/observatorium/observatorium/internal/proxy"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/route"
	"github.com/prometheus/common/version"
)

func main() {
	profile := os.Getenv("PROFILE") != ""

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(10)
		runtime.SetBlockProfileRate(10)
	}

	opts := struct {
		listen               string
		gracePeriod          string
		debugName            string
		logLevel             string
		logFormat            string
		metricsReadEndpoint  string
		metricsWriteEndpoint string
	}{}

	flag.StringVar(&opts.listen, "listen", ":8080", "The address on which internal server runs.")
	flag.StringVar(&opts.gracePeriod, "grace-period", "5s", "The time to wait after an OS interrupt received.")
	flag.StringVar(&opts.debugName, "debug.name", "observatorium", "The Name to add as prefix to log lines.")
	flag.StringVar(&opts.logLevel, "log.level", "info", "The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&opts.logFormat, "log.format", internal.LogFormatLogfmt, "The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&opts.metricsReadEndpoint, "metrics-read-endpoint", "", "The endpoint to which to make write requests for metrics.")
	flag.StringVar(&opts.metricsWriteEndpoint, "metrics-write-endpoint", "", "The endpoint to which to make read requests for metrics.")
	flag.Parse()

	logger := internal.NewLogger(opts.logLevel, opts.logFormat, opts.debugName)
	defer level.Info(logger).Log("msg", "exiting")

	metricsReadEndpoint, err := url.ParseRequestURI(opts.metricsReadEndpoint)
	if err != nil {
		level.Error(logger).Log("msg", "--metrics-read-endpoint is invalid", "err", err)
		return
	}

	metricsWriteEndpoint, err := url.ParseRequestURI(opts.metricsWriteEndpoint)
	if err != nil {
		level.Error(logger).Log("msg", "--metrics-write-endpoint is invalid", "err", err)
		return
	}

	gracePeriod, err := time.ParseDuration(opts.gracePeriod)
	if err != nil {
		level.Error(logger).Log("msg", "--rage-period is invalid", "err", err)
		return
	}

	loggerAdapter := func(template string, args ...interface{}) {
		level.Debug(logger).Log("msg", fmt.Sprintf(template, args))
	}

	// Running in container with limits but with empty/wrong value of GOMAXPROCS env var could lead to throttling by cpu
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS
	undo, err := maxprocs.Set(maxprocs.Logger(loggerAdapter))
	if err != nil {
		level.Error(logger).Log("msg", "failed to set GOMAXPROCS:", "err", err)
	}

	defer undo()

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	var g run.Group
	{
		// Signal channels must be buffered.
		sig := make(chan os.Signal, 1)
		g.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			return nil
		}, func(_ error) {
			level.Info(logger).Log("msg", "caught interrupt")
			close(sig)
		})
	}
	{
		m := internal.NewMetrics(reg)

		router := route.New().WithInstrumentation(m.InstrumentHandler)
		router.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
			promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})).ServeHTTP(w, r)
		})
		router.Get("/prometheus/read", proxy.NewPrometheus("/prometheus/read", metricsReadEndpoint))
		router.Post("/prometheus/write", proxy.NewPrometheus("/prometheus/write", metricsWriteEndpoint))

		prober := internal.NewProber(logger)
		prober.SetHealthy()
		registerProber(router, prober)

		if profile {
			registerProfiler(router)
		}

		srv := &http.Server{Addr: opts.listen, Handler: router}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", opts.listen)
			prober.Ready()

			return srv.ListenAndServe()
		}, func(err error) {
			prober.NotReady(err)

			if err == http.ErrServerClosed {
				level.Warn(logger).Log("msg", "internal server closed unexpectedly")
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
			defer cancel()

			level.Info(logger).Log("msg", "shutting down internal server")
			if err := srv.Shutdown(ctx); err != nil {
				level.Error(logger).Log("msg", "shutting down failed", "err", err)
			}
		})
	}

	level.Info(logger).Log("msg", "starting observatorium")

	if err := g.Run(); err != nil {
		level.Error(logger).Log("msg", "observatorium failed", "err", err)
		os.Exit(1)
	}
}

func registerProfiler(route *route.Router) {
	route.Get("/debug/pprof/", pprof.Index)
	route.Get("/debug/pprof/cmdline", pprof.Cmdline)
	route.Get("/debug/pprof/profile", pprof.Profile)
	route.Get("/debug/pprof/symbol", pprof.Symbol)
	route.Get("/debug/pprof/trace", pprof.Trace)
	route.Get("/debug/pprof/block", func(w http.ResponseWriter, r *http.Request) { pprof.Handler("block").ServeHTTP(w, r) })
	route.Get("/debug/pprof/goroutine", func(w http.ResponseWriter, r *http.Request) { pprof.Handler("goroutine").ServeHTTP(w, r) })
	route.Get("/debug/pprof/heap", func(w http.ResponseWriter, r *http.Request) { pprof.Handler("heap").ServeHTTP(w, r) })
	route.Get("/debug/pprof/threadcreate", func(w http.ResponseWriter, r *http.Request) { pprof.Handler("threadcreate").ServeHTTP(w, r) })
}

func registerProber(route *route.Router, p *internal.Prober) {
	route.Get("/-/healthy", p.HealthyHandler())
	route.Get("/-/ready", p.ReadyHandler())
}
