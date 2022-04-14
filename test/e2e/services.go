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

	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

const (
	apiImage = "quay.io/observatorium/api:local_e2e_test" // Image that is built if you run `make container-test`.

	// Labels matching below thanos v0.24 will fail with "no matchers specified (excluding external labels)" if you specify only tenant matcher. Fixed later on.
	thanosImage = "quay.io/thanos/thanos:main-2021-09-23-177b4f23"
	lokiImage   = "grafana/loki:2.3.0"
	upImage     = "quay.io/observatorium/up:master-2021-02-12-03ef2f2"

	jaegerAllInOneImage = "jaegertracing/all-in-one:1.31"
	otelCollectorImage  = "otel/opentelemetry-collector:0.45.0"
	// Note that if the forwarding collector uses OIDC flow instead of hard-coding
	// the bearer token we would need
	// "otel/opentelemetry-collector-contrib:0.45.0" instead.
	otelFwdCollectorImage = "otel/opentelemetry-collector:0.45.0"

	dexImage              = "dexidp/dex:v2.30.0"
	opaImage              = "openpolicyagent/opa:0.31.0"
	gubernatorImage       = "thrawn01/gubernator:1.0.0-rc.8"
	rulesObjectStoreImage = "quay.io/observatorium/rules-objstore:main-2022-01-19-8650540"

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
	bucket := "obs_rules_test"
	userID := strconv.Itoa(os.Getuid())
	ports := map[string]int{e2edb.AccessPortName: 8090}
	envVars := []string{
		"MINIO_ROOT_USER=" + e2edb.MinioAccessKey,
		"MINIO_ROOT_PASSWORD=" + e2edb.MinioSecretKey,
		"MINIO_BROWSER=" + "off",
		"ENABLE_HTTPS=" + "0",
		// https://docs.min.io/docs/minio-kms-quickstart-guide.html
		"MINIO_KMS_KES_ENDPOINT=" + "https://play.min.io:7373",
		"MINIO_KMS_KES_KEY_FILE=" + "root.key",
		"MINIO_KMS_KES_CERT_FILE=" + "root.cert",
		"MINIO_KMS_KES_KEY_NAME=" + "my-minio-key",
	}
	f := e2e.NewInstrumentedRunnable(e, "rules-minio", ports, e2edb.AccessPortName)
	runnable := f.Init(
		e2e.StartOptions{
			Image: "minio/minio:RELEASE.2022-03-03T21-21-16Z",
			// Create the required bucket before starting minio.
			Command: e2e.NewCommandWithoutEntrypoint("sh", "-c", fmt.Sprintf(
				// Hacky: Create user that matches ID with host ID to be able to remove .minio.sys details on the start.
				// Proper solution would be to contribute/create our own minio image which is non root.
				"useradd -G root -u %v me && mkdir -p %s && chown -R me %s &&"+
					"curl -sSL --tlsv1.2 -O 'https://raw.githubusercontent.com/minio/kes/master/root.key' -O 'https://raw.githubusercontent.com/minio/kes/master/root.cert' && "+
					"cp root.* /home/me/ && "+
					"su - me -s /bin/sh -c 'mkdir -p %s && %s /opt/bin/minio server --address :%v --quiet %v'",
				userID, f.InternalDir(), f.InternalDir(), filepath.Join(f.InternalDir(), bucket), strings.Join(envVars, " "), ports[e2edb.AccessPortName], f.InternalDir()),
			),
			Readiness: e2e.NewHTTPReadinessProbe(e2edb.AccessPortName, "/minio/health/live", 200, 200),
		},
	)

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
	dex *e2e.InstrumentedRunnable,
	token string,
	rateLimiterAddr string,
) {
	createDexYAML(t, e, getContainerName(t, tt, "dex"), getContainerName(t, tt, "observatorium_api"))

	dex = newDexService(e)
	gubernator := newGubernatorService(e)
	opa := newOPAService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(dex, gubernator, opa))

	createTenantsYAML(t, e, dex.InternalEndpoint("https"), opa.InternalEndpoint("http"))

	token, err := obtainToken(dex.Endpoint("https"), getTLSClientConfig(t, e))
	testutil.Ok(t, err)

	return dex, token, gubernator.InternalEndpoint("grpc")
}

func newDexService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"https":          5556,
		"http-telemetry": 5558,
	}

	return e2e.NewInstrumentedRunnable(e, "dex", ports, "http-telemetry").Init(
		e2e.StartOptions{
			Image:   dexImage,
			Command: e2e.NewCommand("dex", "serve", filepath.Join(configsContainerPath, "dex.yaml")),
			Readiness: e2e.NewCmdReadinessProbe(e2e.NewCommand(
				"wget",
				"--no-check-certificate",
				"--quiet",
				"-O", "/dev/null",
				"https://127.0.0.1:5556/dex/.well-known/openid-configuration",
			)),
			User: strconv.Itoa(os.Getuid()),
		},
	)
}

func newGubernatorService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"http": 8880,
		"grpc": 8881,
	}

	return e2e.NewInstrumentedRunnable(e, "gubernator", ports, "http").Init(
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
	)
}

func newThanosReceiveService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"http":         10902,
		"grpc":         10901,
		"remote_write": 19291,
	}

	args := e2e.BuildArgs(map[string]string{
		"--receive.hashrings-file":    filepath.Join(configsContainerPath, "hashrings.json"),
		"--receive.local-endpoint":    "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--label":                     "receive_replica=\"0\"",
		"--receive.default-tenant-id": defaultTenantID,
		"--grpc-address":              "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--http-address":              "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--remote-write.address":      "0.0.0.0:" + strconv.Itoa(ports["remote_write"]),
		"--log.level":                 logLevelError,
		"--tsdb.path":                 "/tmp",
	})

	return e2e.NewInstrumentedRunnable(e, "thanos-receive", ports, "http").Init(
		e2e.StartOptions{
			Image:     thanosImage,
			Command:   e2e.NewCommand("receive", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/-/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

func newLokiService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{"http": 3100}

	args := e2e.BuildArgs(map[string]string{
		"-config.file": filepath.Join(configsContainerPath, "loki.yml"),
		"-target":      "all",
		"-log.level":   logLevelError,
	})

	return e2e.NewInstrumentedRunnable(e, "loki", ports, "http").Init(
		e2e.StartOptions{
			Image:   lokiImage,
			Command: e2e.NewCommandWithoutEntrypoint("loki", args...),
			// It takes ~1m before Loki's ingester starts reporting 200,
			// but it does not seem to affect tests, therefore we accept
			// 503 here as well to save time.
			Readiness: e2e.NewHTTPReadinessProbe("http", "/ready", 200, 503),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

func newRulesBackendService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{"http": 8080, "internal": 8081}

	args := e2e.BuildArgs(map[string]string{
		"--log.level":            logLevelDebug,
		"--web.listen":           ":" + strconv.Itoa(ports["http"]),
		"--web.internal.listen":  ":" + strconv.Itoa(ports["internal"]),
		"--web.healthchecks.url": "http://127.0.0.1:" + strconv.Itoa(ports["http"]),
		"--objstore.config-file": filepath.Join(configsContainerPath, "rules-objstore.yaml"),
	})

	return e2e.NewInstrumentedRunnable(e, "rules_objstore", ports, "internal").Init(
		e2e.StartOptions{
			Image:     rulesObjectStoreImage,
			Command:   e2e.NewCommand("", args...),
			Readiness: e2e.NewHTTPReadinessProbe("internal", "/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

func newOPAService(e e2e.Environment) *e2e.InstrumentedRunnable {
	ports := map[string]int{"http": 8181}

	args := e2e.BuildArgs(map[string]string{
		"--server":           "",
		configsContainerPath: "",
		"--ignore":           "*.json",
	})

	return e2e.NewInstrumentedRunnable(e, "opa", ports, "http").Init(
		e2e.StartOptions{
			Image:     opaImage,
			Command:   e2e.NewCommand("run", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/health", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
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
) (*e2e.InstrumentedRunnable, error) {
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
		"--tls.server.cert-file":            filepath.Join(certsContainerPath, "server.pem"),
		"--tls.server.key-file":             filepath.Join(certsContainerPath, "server.key"),
		"--tls.healthchecks.server-ca-file": filepath.Join(certsContainerPath, "ca.pem"),
		"--rbac.config":                     filepath.Join(configsContainerPath, "rbac.yaml"),
		"--tenants.config":                  filepath.Join(configsContainerPath, "tenants.yaml"),
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

	return e2e.NewInstrumentedRunnable(e, "observatorium_api", ports, "http-internal").Init(
		e2e.StartOptions{
			Image:     apiImage,
			Command:   e2e.NewCommandWithoutEntrypoint("observatorium-api", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http-internal", "/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), nil
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
) (*e2e.InstrumentedRunnable, error) {
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
		"--tls-ca-file":                 filepath.Join(certsContainerPath, "ca.pem"),
		"--tls-client-cert-file":        filepath.Join(certsContainerPath, "client.pem"),
		"--tls-client-private-key-file": filepath.Join(certsContainerPath, "client.key"),
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

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:   upImage,
			Command: e2e.NewCommandWithoutEntrypoint("up", args...),
			User:    strconv.Itoa(os.Getuid()),
		},
	), nil
}
