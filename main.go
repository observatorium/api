package main

import (
	"context"
	"flag"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/observatorium/observatorium/internal"
	"github.com/observatorium/observatorium/internal/proxy"
	"github.com/oklog/run"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
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
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/metrics/read", proxy.NewPrometheus("/metrics/read", metricsReadEndpoint))
		router.HandleFunc("/metrics/write", proxy.NewPrometheus("/metrics/write", metricsWriteEndpoint))

		srv := &http.Server{Addr: opts.listen, Handler: router}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", opts.listen)
			return srv.ListenAndServe()
		}, func(err error) {
			if err == http.ErrServerClosed {
				level.Warn(logger).Log("msg", "internal server closed unexpectedly")
				return
			}

			level.Info(logger).Log("msg", "shutting down internal server")
			ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
			defer cancel()

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
