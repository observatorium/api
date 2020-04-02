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
	"github.com/observatorium/observatorium/internal/proxy"
	"github.com/observatorium/observatorium/internal/server"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"go.uber.org/automaxprocs/maxprocs"
)

type options struct {
	debugMutexProfileFraction int
	debugBlockProfileRate     int
	debugName                 string

	proxyBufferSizeBytes int
	proxyBufferCount     int
	proxyFlushInterval   time.Duration

	listen      string
	gracePeriod time.Duration
	timeout     time.Duration

	logLevel  string
	logFormat string

	metricsUIEndpoint    *url.URL
	metricsReadEndpoint  *url.URL
	metricsWriteEndpoint *url.URL
}

func main() {
	opts, err := parseFlags(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)))
	if err != nil {
		log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr)).Log("msg", "parse flag", "err", err)
		os.Exit(1)
	}

	logger := internal.NewLogger(opts.logLevel, opts.logFormat, opts.debugName)
	defer level.Info(logger).Log("msg", "exiting")

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(opts.debugMutexProfileFraction)
		runtime.SetBlockProfileRate(opts.debugBlockProfileRate)
	}

	// Running in container with limits but with empty/wrong value of GOMAXPROCS env var could lead to throttling by cpu
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS
	undo, err := maxprocs.Set(maxprocs.Logger(func(template string, args ...interface{}) {
		level.Debug(logger).Log("msg", fmt.Sprintf(template, args))
	}))
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

	level.Info(logger).Log("msg", "starting observatorium")

	if err := exec(logger, reg, opts); err != nil {
		level.Error(logger).Log("msg", "observatorium failed", "err", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func exec(logger log.Logger, reg *prometheus.Registry, opts options) error {
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
			server.WithGracePeriod(opts.gracePeriod),
			server.WithTimeout(opts.timeout),
			server.WithProfile(os.Getenv("PROFILE") != ""),
			server.WithMetricUIEndpoint(opts.metricsUIEndpoint),
			server.WithMetricReadEndpoint(opts.metricsReadEndpoint),
			server.WithMetricWriteEndpoint(opts.metricsWriteEndpoint),
			server.WithProxyOptions(
				proxy.WithBufferCount(opts.proxyBufferCount),
				proxy.WithBufferSizeBytes(opts.proxyBufferSizeBytes),
				proxy.WithFlushInterval(opts.proxyFlushInterval),
			),
		)
		g.Add(srv.ListenAndServe, srv.Shutdown)
	}

	return g.Run()
}

func parseFlags(logger log.Logger) (options, error) {
	var (
		rawMetricsUIEndpoint    string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
	)

	opts := options{}

	flag.StringVar(&opts.debugName, "debug.name", "observatorium",
		"The name to add as prefix to log lines.")
	flag.IntVar(&opts.debugMutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The parameter which controls the fraction of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&opts.debugBlockProfileRate, "debug.block-profile-rate", 10,
		"The parameter controls the fraction of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&opts.logLevel, "log.level", "info",
		"The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&opts.logFormat, "log.format", internal.LogFormatLogfmt,
		"The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&opts.listen, "web.listen", ":8080",
		"The address on which internal server runs.")
	flag.DurationVar(&opts.gracePeriod, "web.grace-period", server.DefaultGracePeriod,
		"The time to wait after an OS interrupt received.")
	flag.DurationVar(&opts.timeout, "web.timeout", server.DefaultTimeout,
		"The maximum duration before timing out the request, and closing idle connections.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsUIEndpoint, "metrics.ui.endpoint", "",
		"The endpoint which forward ui requests.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.IntVar(&opts.proxyBufferCount, "proxy.buffer-count", proxy.DefaultBufferCount,
		"Maximum number of of reusable buffer used for copying HTTP reverse proxy responses.")
	flag.IntVar(&opts.proxyBufferSizeBytes, "proxy.buffer-size-bytes", proxy.DefaultBufferSizeBytes,
		"Size (bytes) of reusable buffer used for copying HTTP reverse proxy responses.")
	flag.DurationVar(&opts.proxyFlushInterval, "proxy.flush-interval", proxy.DefaultFlushInterval,
		"The flush interval to flush to the proxy while copying the response body. If zero, no periodic flushing is done. "+
			"A negative value means to flush immediately after each write to the client.")
	flag.Parse()

	if rawMetricsUIEndpoint != "" {
		level.Info(logger).Log("msg", "--metrics.ui.endpoint is not specified, UI will not be accessible")

		metricsUIEndpoint, err := url.ParseRequestURI(rawMetricsUIEndpoint)
		if err != nil {
			return opts, fmt.Errorf("--metrics.ui.endpoint is invalid, raw %s: %w", rawMetricsUIEndpoint, err)
		}

		opts.metricsUIEndpoint = metricsUIEndpoint
	}

	metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
	if err != nil {
		return opts, fmt.Errorf("--metrics.read.endpoint is invalid, raw %s: %w", rawMetricsReadEndpoint, err)
	}

	opts.metricsReadEndpoint = metricsReadEndpoint

	metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
	if err != nil {
		return opts, fmt.Errorf("--metrics.write.endpoint is invalid, raw %s: %w", rawMetricsWriteEndpoint, err)
	}

	opts.metricsWriteEndpoint = metricsWriteEndpoint

	return opts, nil
}
