// +build integration interactive

package e2e

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

const (
	apiImage = "quay.io/observatorium/api:latest"

	thanosImage = "quay.io/thanos/thanos:v0.22.0"
	lokiImage   = "grafana/loki:2.3.0"
	upImage     = "quay.io/observatorium/up:master-2021-02-12-03ef2f2"

	dexImage        = "dexidp/dex:v2.30.0"
	opaImage        = "openpolicyagent/opa:0.31.0"
	gubernatorImage = "thrawn01/gubernator:1.0.0-rc.8"

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

func startServicesForLogs(t *testing.T, e e2e.Environment) (
	logsEndpoint string,
	logsExtEndpoint string,
) {
	loki := newLokiService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(loki))

	return loki.InternalEndpoint("http"), loki.Endpoint("http")
}

// startBaseServices starts and waits until all base services required for the test are ready.
func startBaseServices(t *testing.T, e e2e.Environment, testType testType) (token string, rateLimiterAddr string) {
	createDexYAML(t, e, getContainerName(t, testType, "dex"), getContainerName(t, testType, "observatorium_api"))

	dex := newDexService(e)
	gubernator := newGubernatorService(e)
	opa := newOPAService(e)
	testutil.Ok(t, e2e.StartAndWaitReady(dex, gubernator, opa))

	createTenantsYAML(t, e, dex.InternalEndpoint("https"), opa.InternalEndpoint("http"))

	token, err := obtainToken(dex.Endpoint("https"), getTLSClientConfig(t, e))
	testutil.Ok(t, err)

	return token, gubernator.InternalEndpoint("grpc")
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
	ratelimiterAddr      string
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

	if opts.logsEndpoint != "" {
		args = append(args, "--logs.read.endpoint="+opts.logsEndpoint)
		args = append(args, "--logs.tail.endpoint="+opts.logsEndpoint)
		args = append(args, "--logs.write.endpoint="+opts.logsEndpoint)
	}

	if opts.ratelimiterAddr != "" {
		args = append(args, "--middleware.rate-limiter.grpc-address="+opts.ratelimiterAddr)
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
	testType testType,
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
		"--endpoint-type":               string(testType),
		"--tls-ca-file":                 filepath.Join(certsContainerPath, "ca.pem"),
		"--tls-client-cert-file":        filepath.Join(certsContainerPath, "client.pem"),
		"--tls-client-private-key-file": filepath.Join(certsContainerPath, "client.key"),
		"--endpoint-read":               readEndpoint,
		"--endpoint-write":              writeEndpoint,
		"--log.level":                   logLevelError,
		"--name":                        "observatorium_write",
		"--labels":                      "_id=\"test\"",
	})

	if testType == logs {
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
