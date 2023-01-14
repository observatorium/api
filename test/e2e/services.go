//go:build integration || interactive

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	e2emon "github.com/efficientgo/e2e/monitoring"
)

const (
	apiImage = "quay.io/observatorium/api:local_e2e_test" // Image that is built if you run `make container-test`.

	// Labels matching below thanos v0.24 will fail with "no matchers specified (excluding external labels)" if you specify only tenant matcher. Fixed later on.
	thanosImage = "quay.io/thanos/thanos:main-2022-12-21-c378043"
	lokiImage   = "grafana/loki:2.6.1"
	upImage     = "quay.io/observatorium/up:master-2022-10-27-d8bb06f"

	jaegerAllInOneImage = "jaegertracing/all-in-one:1.31"
	otelCollectorImage  = "otel/opentelemetry-collector:0.45.0"
	// Note that if the forwarding collector uses OIDC flow instead of hard-coding
	// the bearer token we would need
	// "otel/opentelemetry-collector-contrib:0.45.0" instead.
	otelFwdCollectorImage = "otel/opentelemetry-collector:0.45.0"

	dexImage              = "dexidp/dex:v2.30.0"
	opaImage              = "openpolicyagent/opa:0.47.4-static"
	gubernatorImage       = "ghcr.io/mailgun/gubernator:v2.0.0-rc.36"
	rulesObjectStoreImage = "quay.io/observatorium/rules-objstore:main-2023-01-05-26de237"

	logLevelError = "error"
	logLevelDebug = "debug"
)

func startServicesForMetrics(t *testing.T, e e2e.Environment) (
	metricsReadEndpoint string,
	metricsWriteEndpoint string,
	metricsExtReadEndppoint string,
) {
	thanosReceive := newThanosReceiveService(e)
	thanosQuery := e2edb.NewThanosQuerier(
		e,
		"thanos-query",
		[]string{thanosReceive.InternalEndpoint("grpc")},
		e2edb.WithImage(thanosImage),
	)
	testutil.Ok(t, e2e.StartAndWaitReady(thanosReceive, thanosQuery))

	return thanosQuery.InternalEndpoint("http"),
		thanosReceive.InternalEndpoint("remote_write"),
		thanosQuery.Endpoint("http")
}

func startServicesForRules(t *testing.T, e e2e.Environment) (metricsRulesEndpoint string) {
	// Create S3 replacement for rules backend
	const bucket = "obs-rules-test"
	runnable := e2edb.NewMinio(e, "rules-minio", bucket)
	testutil.Ok(t, e2e.StartAndWaitReady(runnable))

	createRulesYAML(t, e, bucket, runnable.InternalEndpoint(e2edb.AccessPortName), e2edb.MinioAccessKey, e2edb.MinioSecretKey)

	rulesBackend := newRulesBackendService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(rulesBackend))

	return rulesBackend.InternalEndpoint("http")
}

func startServicesForLogs(t *testing.T, e e2e.Environment) (
	logsEndpoint string,
	logsExtEndpoint string,
) {

	// Create S3 replacement for rules backend
	bucket := "loki_test"
	runnable := e2edb.NewMinio(e, "loki-minio", bucket)

	testutil.Ok(t, e2e.StartAndWaitReady(runnable))

	createLokiYAML(t, e, e2edb.MinioAccessKey, e2edb.MinioSecretKey, runnable.InternalEndpoint(e2edb.AccessPortName), bucket)

	loki := newLokiService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(loki))

	return loki.InternalEndpoint("http"), loki.Endpoint("http")
}

func startServicesForTraces(t *testing.T, e e2e.Environment) (otlpGRPCEndpoint, jaegerExternalHttpEndpoint, jaegerInternalHttpEndpoint string) {
	jaeger := e.Runnable("jaeger").
		WithPorts(
			map[string]int{
				"jaeger.grpc": 14250, // Receives traces
				"grpc.query":  16685, // Query
				"http.query":  16686, // Query
			}).
		Init(e2e.StartOptions{Image: jaegerAllInOneImage})

	createOtelCollectorConfigYAML(t, e, jaeger.InternalEndpoint("jaeger.grpc"))

	otel := e.Runnable("otel-collector").
		WithPorts(
			map[string]int{
				"grpc": 4317,
				"http": 4318,
			}).
		Init(e2e.StartOptions{
			Image: otelCollectorImage,
			Volumes: []string{
				// We do an explicit bind mount, because the OTel user
				// may not have permission to view files using /shared/config
				fmt.Sprintf("%s:/conf/collector.yaml",
					filepath.Join(filepath.Join(e.SharedDir(), configSharedDir, "collector.yaml"))),
			},
			Command: e2e.Command{
				Args: []string{"--config=/conf/collector.yaml"},
			},
		})

	testutil.Ok(t, e2e.StartAndWaitReady(jaeger))
	testutil.Ok(t, e2e.StartAndWaitReady(otel))

	return otel.InternalEndpoint("grpc"), jaeger.Endpoint("http.query"), jaeger.InternalEndpoint("http.query")
}

// startBaseServices starts and waits until all base services required for the test are ready.
func startBaseServices(t *testing.T, e e2e.Environment, tt testType) (
	dex *e2emon.InstrumentedRunnable,
	token string,
	rateLimiterAddr string,
) {
	createDexYAML(t, e, getContainerName(t, tt, "dex"), getContainerName(t, tt, "observatorium_api"))

	dex = newDexService(e)
	gubernator := newGubernatorService(e)
	opa := newOPAService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(dex, gubernator, opa))

	createTenantsYAML(t, e, dex.InternalEndpoint("https"), opa.InternalEndpoint("http"), getContainerName(t, tt, "observatorium_api"))

	token, err := obtainToken(dex.Endpoint("https"), getTLSClientConfig(t, e))
	testutil.Ok(t, err)

	return dex, token, gubernator.InternalEndpoint("grpc")
}

func newDexService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{
		"https":          5556,
		"http-telemetry": 5558,
	}

	return e2emon.AsInstrumented(e.Runnable("dex").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:   dexImage,
			Command: e2e.NewCommand("dex", "serve", filepath.Join(e.SharedDir(), configSharedDir, "dex.yaml")),
			Readiness: e2e.NewCmdReadinessProbe(e2e.NewCommand(
				"wget",
				"--no-check-certificate",
				"--quiet",
				"-O", "/dev/null",
				"https://127.0.0.1:5556/dex/.well-known/openid-configuration",
			)),
			User: strconv.Itoa(os.Getuid()),
		},
	), "http-telemetry")
}

func newGubernatorService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{
		"http": 8880,
		"grpc": 8881,
	}
	return e2emon.AsInstrumented(e.Runnable("gubernator").WithPorts(ports).Init(
		e2e.StartOptions{
			Image: gubernatorImage,
			EnvVars: map[string]string{
				"GUBER_HTTP_ADDRESS":           "0.0.0.0:" + strconv.Itoa(ports["http"]),
				"GUBER_GRPC_ADDRESS":           "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
				"GUBER_MEMBERLIST_KNOWN_NODES": "127.0.0.1:7946",
			},
			Command:   e2e.NewCommand("gubernator"),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/v1/HealthCheck", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), "http")
}

func newThanosReceiveService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{
		"http":         10902,
		"grpc":         10901,
		"remote_write": 19291,
	}

	args := e2e.BuildArgs(map[string]string{
		"--receive.hashrings-file":    filepath.Join(e.SharedDir(), configSharedDir, "hashrings.json"),
		"--receive.local-endpoint":    "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--label":                     "receive_replica=\"0\"",
		"--receive.default-tenant-id": defaultTenantID,
		"--grpc-address":              "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--http-address":              "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--remote-write.address":      "0.0.0.0:" + strconv.Itoa(ports["remote_write"]),
		"--log.level":                 logLevelError,
		"--tsdb.path":                 "/tmp",
	})

	return e2emon.AsInstrumented(e.Runnable("thanos-receive").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:     thanosImage,
			Command:   e2e.NewCommand("receive", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/-/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), "http")
}

func newLokiService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{"http": 3100, "grpc": 9095}

	args := e2e.BuildArgs(map[string]string{
		"-config.file":                filepath.Join(e.SharedDir(), configSharedDir, "loki.yml"),
		"-server.grpc-listen-address": "0.0.0.0",
		"-server.grpc-listen-port":    strconv.Itoa(ports["grpc"]),
		"-server.http-listen-address": "0.0.0.0",
		"-server.http-listen-port":    strconv.Itoa(ports["http"]),
		"-target":                     "all",
		"-log.level":                  logLevelError,
	})

	return e2emon.AsInstrumented(e.Runnable("loki").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:   lokiImage,
			Command: e2e.NewCommandWithoutEntrypoint("loki", args...),
			// It takes ~1m before Loki's ingester starts reporting 200,
			// but it does not seem to affect tests, therefore we accept
			// 503 here as well to save time.
			Readiness: e2e.NewHTTPReadinessProbe("http", "/ready", 200, 503),
			User:      strconv.Itoa(os.Getuid()),
		},
	), "http")
}

func newRulesBackendService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{"http": 8080, "internal": 8081}

	args := e2e.BuildArgs(map[string]string{
		"--log.level":            logLevelDebug,
		"--web.listen":           ":" + strconv.Itoa(ports["http"]),
		"--web.internal.listen":  ":" + strconv.Itoa(ports["internal"]),
		"--web.healthchecks.url": "http://127.0.0.1:" + strconv.Itoa(ports["http"]),
		"--objstore.config-file": filepath.Join(e.SharedDir(), configSharedDir, "rules-objstore.yaml"),
	})

	return e2emon.AsInstrumented(e.Runnable("rules_objstore").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:     rulesObjectStoreImage,
			Command:   e2e.NewCommand("", args...),
			Readiness: e2e.NewHTTPReadinessProbe("internal", "/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), "internal")
}

func newOPAService(e e2e.Environment) *e2emon.InstrumentedRunnable {
	ports := map[string]int{"http": 8181}

	args := e2e.BuildArgs(map[string]string{
		"--server": "",
		filepath.Join(e.SharedDir(), configSharedDir): "",
		"--ignore": "*.json",
	})

	return e2emon.AsInstrumented(e.Runnable("opa").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:     opaImage,
			Command:   e2e.NewCommand("run", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/health", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), "http")
}

type apiOptions struct {
	logsEndpoint         string
	metricsReadEndpoint  string
	metricsWriteEndpoint string
	metricsRulesEndpoint string
	ratelimiterAddr      string
	tracesWriteEndpoint  string
	gRPCListenEndpoint   string
	jaegerQueryEndpoint  string

	// "experimental.traces.read.endpoint-template" value.
	tracesExperimentalTemplateReadEndpoint string
}

type apiOption func(*apiOptions)

func withLogsEndpoints(endpoint string) apiOption {
	return func(o *apiOptions) {
		o.logsEndpoint = endpoint
	}
}

func withMetricsEndpoints(readEndpoint string, writeEndpoint string) apiOption {
	return func(o *apiOptions) {
		o.metricsReadEndpoint = readEndpoint
		o.metricsWriteEndpoint = writeEndpoint
	}
}

func withOtelTraceEndpoint(exportEndpoint string) apiOption {
	return func(o *apiOptions) {
		o.tracesWriteEndpoint = exportEndpoint
	}
}

func withGRPCListenEndpoint(listenEndpoint string) apiOption {
	return func(o *apiOptions) {
		o.gRPCListenEndpoint = listenEndpoint
	}
}

func withJaegerEndpoint(jaegerQueryEndpoint string) apiOption {
	return func(o *apiOptions) {
		o.jaegerQueryEndpoint = jaegerQueryEndpoint
	}
}

func withExperimentalJaegerTemplateEndpoint(jaegerQueryEndpointTemplate string) apiOption {
	return func(o *apiOptions) {
		o.tracesExperimentalTemplateReadEndpoint = jaegerQueryEndpointTemplate
	}
}

func withRulesEndpoint(rulesEndpoint string) apiOption {
	return func(o *apiOptions) {
		o.metricsRulesEndpoint = rulesEndpoint
	}
}

func withRateLimiter(addr string) apiOption {
	return func(o *apiOptions) {
		o.ratelimiterAddr = addr
	}
}

func newObservatoriumAPIService(
	e e2e.Environment,
	options ...apiOption,
) (*e2emon.InstrumentedRunnable, error) {
	opts := apiOptions{}
	for _, o := range options {
		o(&opts)
	}

	ports := map[string]int{
		"https":         8443,
		"http-internal": 8448,
	}

	args := e2e.BuildArgs(map[string]string{
		"--web.listen":                      ":" + strconv.Itoa(ports["https"]),
		"--web.internal.listen":             ":" + strconv.Itoa(ports["http-internal"]),
		"--web.healthchecks.url":            "https://127.0.0.1:8443",
		"--tls.server.cert-file":            filepath.Join(e.SharedDir(), certsSharedDir, "server.pem"),
		"--tls.server.key-file":             filepath.Join(e.SharedDir(), certsSharedDir, "server.key"),
		"--tls.healthchecks.server-ca-file": filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem"),
		"--rbac.config":                     filepath.Join(e.SharedDir(), configSharedDir, "rbac.yaml"),
		"--tenants.config":                  filepath.Join(e.SharedDir(), configSharedDir, "tenants.yaml"),
		"--log.level":                       logLevelDebug,
	})

	if opts.metricsReadEndpoint != "" && opts.metricsWriteEndpoint != "" {
		args = append(args, "--metrics.read.endpoint="+opts.metricsReadEndpoint)
		args = append(args, "--metrics.write.endpoint="+opts.metricsWriteEndpoint)
	}

	if opts.metricsRulesEndpoint != "" {
		args = append(args, "--metrics.rules.endpoint="+opts.metricsRulesEndpoint)
	}

	if opts.logsEndpoint != "" {
		args = append(args, "--logs.read.endpoint="+opts.logsEndpoint)
		args = append(args, "--logs.tail.endpoint="+opts.logsEndpoint)
		args = append(args, "--logs.write.endpoint="+opts.logsEndpoint)
		args = append(args, "--logs.rules.endpoint="+opts.logsEndpoint)
	}

	if opts.ratelimiterAddr != "" {
		args = append(args, "--middleware.rate-limiter.grpc-address="+opts.ratelimiterAddr)
	}

	if opts.tracesWriteEndpoint != "" {
		args = append(args, "--traces.write.endpoint="+opts.tracesWriteEndpoint)
	}

	if opts.tracesExperimentalTemplateReadEndpoint != "" {
		args = append(args, "--experimental.traces.read.endpoint-template="+opts.tracesExperimentalTemplateReadEndpoint)
	}

	if opts.jaegerQueryEndpoint != "" {
		args = append(args, "--traces.read.endpoint="+opts.jaegerQueryEndpoint)
	}

	if opts.gRPCListenEndpoint != "" {
		gRPCChunks := strings.SplitN(opts.gRPCListenEndpoint, ":", 2)
		if len(gRPCChunks) != 2 {
			return nil, fmt.Errorf("Invalid gRPC Listen Endpoint: %q", opts.gRPCListenEndpoint)
		}
		gRPCPort, err := strconv.Atoi(gRPCChunks[1])
		if err != nil {
			return nil, err
		}
		ports["grpc"] = gRPCPort

		args = append(args, "--grpc.listen="+opts.gRPCListenEndpoint)
	}

	return e2emon.AsInstrumented(e.Runnable("observatorium-api").WithPorts(ports).Init(
		e2e.StartOptions{
			Image:     apiImage,
			Command:   e2e.NewCommandWithoutEntrypoint("observatorium-api", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http-internal", "/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		}), "http-internal"), nil
}

type runParams struct {
	initialDelay string
	period       string
	latency      string
	threshold    string
	duration     string
}

type upOptions struct {
	token     string
	runParams *runParams
}

type upOption func(*upOptions)

func withToken(token string) upOption {
	return func(o *upOptions) {
		o.token = token
	}
}

func withRunParameters(params *runParams) upOption {
	return func(o *upOptions) {
		o.runParams = params
	}
}

func newUpRun(
	env e2e.Environment,
	name string,
	tt testType,
	readEndpoint, writeEndpoint string,
	options ...upOption,
) (*e2emon.InstrumentedRunnable, error) {
	opts := upOptions{}
	for _, o := range options {
		o(&opts)
	}

	timeFn := func() string { return strconv.FormatInt(time.Now().UnixNano(), 10) }
	ports := map[string]int{
		"http": 8888,
	}

	args := e2e.BuildArgs(map[string]string{
		"--listen":                      "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--endpoint-type":               string(tt),
		"--tls-ca-file":                 filepath.Join(env.SharedDir(), certsSharedDir, "ca.pem"),
		"--tls-client-cert-file":        filepath.Join(env.SharedDir(), certsSharedDir, "client.pem"),
		"--tls-client-private-key-file": filepath.Join(env.SharedDir(), certsSharedDir, "client.key"),
		"--endpoint-read":               readEndpoint,
		"--endpoint-write":              writeEndpoint,
		"--log.level":                   logLevelError,
		"--name":                        "observatorium_write",
		"--labels":                      "_id=\"test\"",
	})

	if tt == logs {
		args = append(args, "--logs=[\""+timeFn()+"\",\"log line 1\"]")
	}

	if opts.token != "" {
		args = append(args, "--token="+opts.token)
	}

	if opts.runParams != nil {
		if opts.runParams.initialDelay != "" {
			args = append(args, "--initial-query-delay="+opts.runParams.initialDelay)
		}
		if opts.runParams.duration != "" {
			args = append(args, "--duration="+opts.runParams.duration)
		}
		if opts.runParams.latency != "" {
			args = append(args, "--latency="+opts.runParams.latency)
		}
		if opts.runParams.threshold != "" {
			args = append(args, "--threshold="+opts.runParams.threshold)
		}
		if opts.runParams.period != "" {
			args = append(args, "--period="+opts.runParams.period)
		}
	}

	return e2emon.AsInstrumented(env.Runnable(name).WithPorts(ports).Init(
		e2e.StartOptions{
			Image:     upImage,
			Command:   e2e.NewCommandWithoutEntrypoint("up", args...),
			User:      strconv.Itoa(os.Getuid()),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/metrics", 200, 200),
		},
	), "http"), nil
}
