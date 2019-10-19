package main

import (
	"context"
	"flag"
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

	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
		router := http.NewServeMux()
		router.Handle("/metrics", promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
		router.HandleFunc("/prometheus/read", proxy.NewPrometheus("/prometheus/read", metricsReadEndpoint))
		router.HandleFunc("/prometheus/write", proxy.NewPrometheus("/prometheus/write", metricsWriteEndpoint))

		prober := internal.NewProber(logger)
		prober.SetHealthy()
		registerProber(router, prober)

		if profile {
			registerProfile(router)
		}

		srv := &http.Server{Addr: opts.listen, Handler: router}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", opts.listen)
			prober.SetReady()

			return srv.ListenAndServe()
		}, func(err error) {
			prober.SetNotReady(err)

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

func registerProfile(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
}

func registerProber(mux *http.ServeMux, p *internal.Prober) {
	mux.HandleFunc("/-/healthy", p.HealthyHandlerFunc())
	mux.HandleFunc("/-/ready", p.ReadyHandlerFunc())
}
