package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/observatorium/up/pkg/auth"
	"github.com/observatorium/up/pkg/instr"
	"github.com/observatorium/up/pkg/logs"
	"github.com/observatorium/up/pkg/metrics"
	"github.com/observatorium/up/pkg/options"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	promapiv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql/parser"
	"gopkg.in/yaml.v2"
)

const (
	numOfEndpoints        = 2
	timeoutBetweenQueries = 100 * time.Millisecond
)

type queriesFile struct {
	Queries []options.QuerySpec `yaml:"queries"`
}

func main() {
	l := log.WithPrefix(log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr)), "name", "up")
	l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)
	l = log.WithPrefix(l, "caller", log.DefaultCaller)

	opts, err := parseFlags(l)
	if err != nil {
		level.Error(l).Log("msg", "could not parse command line flags", "err", err)
		os.Exit(1)
	}

	l = level.NewFilter(l, opts.LogLevel)
	l = log.WithPrefix(l, "caller", log.DefaultCaller)

	reg := prometheus.NewRegistry()
	m := instr.RegisterMetrics(reg)

	// Error channel to gather failures
	ch := make(chan error, numOfEndpoints)

	g := &run.Group{}
	{
		// Signal chans must be buffered.
		sig := make(chan os.Signal, 1)
		g.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			level.Info(l).Log("msg", "caught interrupt")
			return nil
		}, func(_ error) {
			close(sig)
		})
	}
	// Schedule HTTP server
	scheduleHTTPServer(l, opts, reg, g)

	ctx := context.Background()

	var cancel context.CancelFunc
	if opts.Duration != 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Duration)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	if opts.WriteEndpoint != nil {
		g.Add(func() error {
			l := log.With(l, "component", "writer")
			level.Info(l).Log("msg", "starting the writer")

			return runPeriodically(ctx, opts, m.RemoteWriteRequests, l, ch, func(rCtx context.Context) {
				if err := write(rCtx, l, opts); err != nil {
					m.RemoteWriteRequests.WithLabelValues("error").Inc()
					level.Error(l).Log("msg", "failed to make request", "err", err)
				} else {
					m.RemoteWriteRequests.WithLabelValues("success").Inc()
				}
			})
		}, func(_ error) {
			cancel()
		})
	}

	if opts.ReadEndpoint != nil && opts.WriteEndpoint != nil {
		g.Add(func() error {
			l := log.With(l, "component", "reader")
			level.Info(l).Log("msg", "starting the reader")

			// Wait for at least one period before start reading metrics.
			level.Info(l).Log("msg", "waiting for initial delay before querying", "type", opts.EndpointType)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(opts.InitialQueryDelay):
			}

			level.Info(l).Log("msg", "start querying", "type", opts.EndpointType)

			return runPeriodically(ctx, opts, m.QueryResponses, l, ch, func(rCtx context.Context) {
				if err := read(rCtx, l, m, opts); err != nil {
					m.QueryResponses.WithLabelValues("error").Inc()
					level.Error(l).Log("msg", "failed to query", "err", err)
				} else {
					m.QueryResponses.WithLabelValues("success").Inc()
				}
			})
		}, func(_ error) {
			cancel()
		})
	}

	if opts.ReadEndpoint != nil && opts.Queries != nil {
		addCustomQueryRunGroup(ctx, g, l, opts, m, cancel)
	}

	if err := g.Run(); err != nil {
		level.Info(l).Log("msg", "run group exited with error", "err", err)
	}

	close(ch)

	fail := false
	for err := range ch {
		fail = true

		level.Error(l).Log("err", err)
	}

	if fail {
		level.Error(l).Log("msg", "up failed")
		os.Exit(1)
	}

	level.Info(l).Log("msg", "up completed its mission!")
}

func write(ctx context.Context, l log.Logger, opts options.Options) error {
	switch opts.EndpointType {
	case options.MetricsEndpointType:
		return metrics.Write(ctx, opts.WriteEndpoint, opts.Token, metrics.Generate(opts.Labels), l, opts.TLS)
	case options.LogsEndpointType:
		return logs.Write(ctx, opts.WriteEndpoint, opts.Token, logs.Generate(opts.Labels, opts.Logs), l, opts.TLS)
	}

	return nil
}

func read(ctx context.Context, l log.Logger, m instr.Metrics, opts options.Options) error {
	switch opts.EndpointType {
	case options.MetricsEndpointType:
		return metrics.Read(ctx, opts.ReadEndpoint, opts.Token, opts.Labels, -1*opts.InitialQueryDelay, opts.Latency, m, l, opts.TLS)
	case options.LogsEndpointType:
		return logs.Read(ctx, opts.ReadEndpoint, opts.Token, opts.Labels, -1*opts.InitialQueryDelay, opts.Latency, m, l, opts.TLS)
	}

	return nil
}

func query(ctx context.Context, l log.Logger, q options.QuerySpec, opts options.Options) (promapiv1.Warnings, error) {
	switch opts.EndpointType {
	case options.MetricsEndpointType:
		return metrics.Query(ctx, l, opts.ReadEndpoint, opts.Token, q, opts.TLS)
	case options.LogsEndpointType:
		return nil, errors.Errorf("not implemented for logs")
	}

	return nil, nil
}

func addCustomQueryRunGroup(ctx context.Context, g *run.Group, l log.Logger, opts options.Options, m instr.Metrics, cancel func()) {
	g.Add(func() error {
		l := log.With(l, "component", "query-reader")
		level.Info(l).Log("msg", "starting the reader for queries")

		// Wait for at least one period before start reading metrics.
		level.Info(l).Log("msg", "waiting for initial delay before querying specified queries")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.InitialQueryDelay):
		}

		level.Info(l).Log("msg", "start querying for specified queries")

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				for _, q := range opts.Queries {
					select {
					case <-ctx.Done():
						return nil
					default:
						t := time.Now()
						warn, err := query(ctx, l, q, opts)
						duration := time.Since(t).Seconds()
						if err != nil {
							level.Info(l).Log(
								"msg", "failed to execute specified query",
								"name", q.Name,
								"duration", duration,
								"warnings", fmt.Sprintf("%#+v", warn),
								"err", err,
							)
							m.CustomQueryErrors.WithLabelValues(q.Name).Inc()
						} else {
							level.Debug(l).Log("msg", "successfully executed specified query",
								"name", q.Name,
								"duration", duration,
								"warnings", fmt.Sprintf("%#+v", warn),
							)
							m.CustomQueryLastDuration.WithLabelValues(q.Name).Set(duration)
						}
						m.CustomQueryExecuted.WithLabelValues(q.Name).Inc()
					}
					time.Sleep(timeoutBetweenQueries)
				}
				time.Sleep(timeoutBetweenQueries)
			}
		}
	}, func(_ error) {
		cancel()
	})
}

func runPeriodically(ctx context.Context, opts options.Options, c *prometheus.CounterVec, l log.Logger, ch chan error,
	f func(rCtx context.Context)) error {
	var (
		t        = time.NewTicker(opts.Period)
		deadline time.Time
		rCtx     context.Context
		rCancel  context.CancelFunc
	)

	for {
		select {
		case <-t.C:
			// NOTICE: Do not propagate parent context to prevent cancellation of in-flight request.
			// It will be cancelled after the deadline.
			deadline = time.Now().Add(opts.Period)
			rCtx, rCancel = context.WithDeadline(context.Background(), deadline)

			// Will only get scheduled once per period and guaranteed to get cancelled after deadline.
			go func() {
				defer rCancel() // Make sure context gets cancelled even if execution panics.

				f(rCtx)
			}()
		case <-ctx.Done():
			t.Stop()

			select {
			// If it gets immediately cancelled, zero value of deadline won't cause a lock!
			case <-time.After(time.Until(deadline)):
				rCancel()
			case <-rCtx.Done():
			}

			return reportResults(l, ch, c, opts.SuccessThreshold)
		}
	}
}

func reportResults(l log.Logger, ch chan error, c *prometheus.CounterVec, threshold float64) error {
	metrics := make(chan prometheus.Metric, numOfEndpoints)
	c.Collect(metrics)
	close(metrics)

	var success, failures float64

	for m := range metrics {
		m1 := &dto.Metric{}
		if err := m.Write(m1); err != nil {
			level.Warn(l).Log("msg", "cannot read success and error count from prometheus counter", "err", err)
		}

		for _, l := range m1.Label {
			switch *l.Value {
			case "error":
				failures = m1.GetCounter().GetValue()
			case "success":
				success = m1.GetCounter().GetValue()
			}
		}
	}

	level.Info(l).Log("msg", "number of requests", "success", success, "errors", failures)

	ratio := success / (success + failures)
	if ratio < threshold {
		level.Error(l).Log("msg", "ratio is below threshold")

		err := errors.Errorf("failed with less than %2.f%% success ratio - actual %2.f%%", threshold*100, ratio*100) //nolint:gomnd
		ch <- err

		return err
	}

	return nil
}

// Helpers

func parseFlags(l log.Logger) (options.Options, error) {
	var (
		rawEndpointType  string
		rawWriteEndpoint string
		rawReadEndpoint  string
		rawLogLevel      string
		queriesFileName  string
		tokenFile        string
		token            string
	)

	opts := options.Options{}

	flag.StringVar(&rawLogLevel, "log.level", "info", "The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&rawEndpointType, "endpoint-type", "", "The endpoint type. Options: 'logs', 'metrics'.")
	flag.StringVar(&rawWriteEndpoint, "endpoint-write", "", "The endpoint to which to make remote-write requests.")
	flag.StringVar(&rawReadEndpoint, "endpoint-read", "", "The endpoint to which to make query requests.")
	flag.Var(&opts.Labels, "labels", "The labels in addition to '__name__' that should be applied to remote-write requests.")
	flag.StringVar(&opts.Listen, "listen", ":8080", "The address on which internal server runs.")
	flag.Var(&opts.Logs, "logs", "The logs that should be sent to remote-write requests.")
	flag.StringVar(&opts.Name, "name", "up", "The name of the metric to send in remote-write requests.")
	flag.StringVar(&token, "token", "",
		"The bearer token to set in the authorization header on requests. Takes predence over --token-file if set.")
	flag.StringVar(&tokenFile, "token-file", "",
		"The file from which to read a bearer token to set in the authorization header on requests.")
	flag.StringVar(&queriesFileName, "queries-file", "", "A file containing queries to run against the read endpoint.")
	flag.DurationVar(&opts.Period, "period", 5*time.Second, "The time to wait between remote-write requests.") //nolint:gomnd
	flag.DurationVar(&opts.Duration, "duration", 5*time.Minute,                                                //nolint:gomnd
		"The duration of the up command to run until it stops. If 0 it will not stop until the process is terminated.")
	flag.Float64Var(&opts.SuccessThreshold, "threshold", 0.9, "The percentage of successful requests needed to succeed overall. 0 - 1.")
	flag.DurationVar(&opts.Latency, "latency", 15*time.Second, //nolint:gomnd
		"The maximum allowable latency between writing and reading.")
	flag.DurationVar(&opts.InitialQueryDelay, "initial-query-delay", 5*time.Second, //nolint:gomnd
		"The time to wait before executing the first query.")
	flag.StringVar(&opts.TLS.Cert, "tls-client-cert-file", "",
		"File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&opts.TLS.Key, "tls-client-private-key-file", "",
		"File containing the default x509 private key matching --tls-cert-file. Leave blank to disable TLS.")
	flag.StringVar(&opts.TLS.CACert, "tls-ca-file", "",
		"File containing the TLS CA to use against servers for verification. If no CA is specified, there won't be any verification.")
	flag.Parse()

	return buildOptionsFromFlags(l, opts, rawLogLevel, rawEndpointType, rawWriteEndpoint, rawReadEndpoint, queriesFileName, token, tokenFile)
}

func buildOptionsFromFlags(
	l log.Logger,
	opts options.Options,
	rawLogLevel, rawEndpointType, rawWriteEndpoint, rawReadEndpoint, queriesFileName, token, tokenFile string,
) (options.Options, error) {
	var err error

	err = parseLogLevel(&opts, rawLogLevel)
	if err != nil {
		return opts, errors.Wrap(err, "parsing log level")
	}

	err = parseEndpointType(&opts, rawEndpointType)
	if err != nil {
		return opts, errors.Wrap(err, "parsing endpoint type")
	}

	err = parseWriteEndpoint(&opts, l, rawWriteEndpoint)
	if err != nil {
		return opts, errors.Wrap(err, "parsing write endpoint")
	}

	err = parseReadEndpoint(&opts, l, rawReadEndpoint)
	if err != nil {
		return opts, errors.Wrap(err, "parsing read endpoint")
	}

	err = parseQueriesFileName(&opts, l, queriesFileName)
	if err != nil {
		return opts, errors.Wrap(err, "parsing queries file name")
	}

	if opts.Latency <= opts.Period {
		return opts, errors.Errorf("--latency cannot be less than period")
	}

	opts.Labels = append(opts.Labels, prompb.Label{
		Name:  "__name__",
		Value: opts.Name,
	})

	opts.Token = tokenProvider(token, tokenFile)

	return opts, err
}

func parseLogLevel(opts *options.Options, rawLogLevel string) error {
	switch rawLogLevel {
	case "error":
		opts.LogLevel = level.AllowError()
	case "warn":
		opts.LogLevel = level.AllowWarn()
	case "info":
		opts.LogLevel = level.AllowInfo()
	case "debug":
		opts.LogLevel = level.AllowDebug()
	default:
		return errors.Errorf("unexpected log level")
	}

	return nil
}

func parseEndpointType(opts *options.Options, rawEndpointType string) error {
	switch options.EndpointType(rawEndpointType) {
	case options.LogsEndpointType:
		opts.EndpointType = options.LogsEndpointType
	case options.MetricsEndpointType:
		opts.EndpointType = options.MetricsEndpointType
	default:
		return errors.Errorf("unexpected endpoint type")
	}

	return nil
}

func parseWriteEndpoint(opts *options.Options, l log.Logger, rawWriteEndpoint string) error {
	if rawWriteEndpoint != "" {
		writeEndpoint, err := url.ParseRequestURI(rawWriteEndpoint)
		if err != nil {
			return fmt.Errorf("--endpoint-write is invalid: %w", err)
		}

		opts.WriteEndpoint = writeEndpoint
	} else {
		l.Log("msg", "no write endpoint specified, no write tests being performed")
	}

	return nil
}

func parseReadEndpoint(opts *options.Options, l log.Logger, rawReadEndpoint string) error {
	if rawReadEndpoint != "" {
		readEndpoint, err := url.ParseRequestURI(rawReadEndpoint)
		if err != nil {
			return fmt.Errorf("--endpoint-read is invalid: %w", err)
		}

		opts.ReadEndpoint = readEndpoint
	} else {
		l.Log("msg", "no read endpoint specified, no read tests being performed")
	}

	return nil
}

func parseQueriesFileName(opts *options.Options, l log.Logger, queriesFileName string) error {
	if queriesFileName != "" {
		b, err := ioutil.ReadFile(queriesFileName)
		if err != nil {
			return fmt.Errorf("--queries-file is invalid: %w", err)
		}

		qf := queriesFile{}
		err = yaml.Unmarshal(b, &qf)

		if err != nil {
			return fmt.Errorf("--queries-file content is invalid: %w", err)
		}

		l.Log("msg", fmt.Sprintf("%d queries configured to be queried periodically", len(qf.Queries)))

		// validate queries
		for _, q := range qf.Queries {
			_, err = parser.ParseExpr(q.Query)
			if err != nil {
				return fmt.Errorf("query %q in --queries-file content is invalid: %w", q.Name, err)
			}
		}

		opts.Queries = qf.Queries
	}

	return nil
}

func tokenProvider(token, tokenFile string) auth.TokenProvider {
	var res auth.TokenProvider

	res = auth.NewNoOpTokenProvider()
	if tokenFile != "" {
		res = auth.NewFileToken(tokenFile)
	}

	if token != "" {
		res = auth.NewStaticToken(token)
	}

	return res
}

func scheduleHTTPServer(l log.Logger, opts options.Options, reg *prometheus.Registry, g *run.Group) {
	logger := log.With(l, "component", "http")
	router := http.NewServeMux()
	router.Handle("/metrics", promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	router.HandleFunc("/debug/pprof/", pprof.Index)

	srv := &http.Server{Addr: opts.Listen, Handler: router}

	g.Add(func() error {
		level.Info(logger).Log("msg", "starting the HTTP server", "address", opts.Listen)
		return srv.ListenAndServe()
	}, func(err error) {
		if errors.Is(err, http.ErrServerClosed) {
			level.Warn(logger).Log("msg", "internal server closed unexpectedly")
			return
		}
		level.Info(logger).Log("msg", "shutting down internal server")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			stdlog.Fatal(err)
		}
	})
}
