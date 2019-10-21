package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/observatorium/observatorium/internal"
	"github.com/observatorium/observatorium/internal/server"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
)

func main() {
	opts := struct {
		debugMutexProfileFraction int
		debugBlockProfileRate     int

		listen               string
		gracePeriod          string
		debugName            string
		logLevel             string
		logFormat            string
		metricsQueryEndpoint string
		metricsWriteEndpoint string
	}{}

	flag.StringVar(&opts.listen, "listen", ":8080", "The address on which internal server runs.")
	flag.StringVar(&opts.gracePeriod, "grace-period", "5s", "The time to wait after an OS interrupt received.")
	flag.StringVar(&opts.debugName, "debug.name", "observatorium", "The name to add as prefix to log lines.")
	flag.IntVar(&opts.debugMutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The parameter which controls the fraction of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&opts.debugBlockProfileRate, "debug.block-profile-rate", 10,
		"The parameter controls the fraction of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&opts.logLevel, "log.level", "info", "The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&opts.logFormat, "log.format", internal.LogFormatLogfmt, "The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&opts.metricsQueryEndpoint, "metrics-query-endpoint", "", "The endpoint which to make queries against for metrics.")
	flag.StringVar(&opts.metricsWriteEndpoint, "metrics-write-endpoint", "", "The endpoint which to make write requests against for metrics.")
	flag.Parse()

	debug := os.Getenv("DEBUG") != ""

	if debug {
		runtime.SetMutexProfileFraction(opts.debugMutexProfileFraction)
		runtime.SetBlockProfileRate(opts.debugBlockProfileRate)
	}

	logger := internal.NewLogger(opts.logLevel, opts.logFormat, opts.debugName)
	defer level.Info(logger).Log("msg", "exiting")

	metricsQueryEndpoint, err := url.ParseRequestURI(opts.metricsQueryEndpoint)
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
		srv := server.New(
			logger,
			reg,
			server.WithListen(opts.listen),
			server.WithGracePeriod(gracePeriod),
			server.WithProfile(os.Getenv("PROFILE") != ""),
			server.WithMetricQueryEndpoint(metricsQueryEndpoint),
			server.WithMetricWriteEndpoint(metricsWriteEndpoint),
		)
		g.Add(srv.ListenAndServe, srv.Shutdown)
	}

	level.Info(logger).Log("msg", "starting observatorium")

	if err := g.Run(); err != nil {
		level.Error(logger).Log("msg", "observatorium failed", "err", err)
		os.Exit(1)
	}
}
