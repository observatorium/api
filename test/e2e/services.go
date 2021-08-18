package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/efficientgo/e2e"
)

const (
	thanosImage = "quay.io/thanos/thanos:v0.22.0"
	lokiImage   = "grafana/loki:2.3.0"
	upImage     = "quay.io/observatorium/up:master-2021-02-12-03ef2f2"

	dexImage = "dexidp/dex:v2.30.0"
	opaImage = "openpolicyagent/opa:0.31.0"
	// websocatImage   = ""
	gubernatorImage = "thrawn01/gubernator:1.0.0-rc.8"

	apiImage = "quay.io/observatorium/api:latest"

	dockerLocalSharedDir = "/shared"
	logLevelInfo         = "info"
)

func newDexService(env e2e.Environment, name string, containerConfigPath string) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"https":          5556,
		"http-telemetry": 5558,
	}

	return e2e.NewInstrumentedRunnable(env, name, ports, "http-telemetry").Init(
		e2e.StartOptions{
			Image: dexImage,
			// TODO: With or without entrypoint?
			Command: e2e.NewCommandWithoutEntrypoint("dex", "serve", containerConfigPath),
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

func newGubernatorService(env e2e.Environment, name string) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"http": 8880,
		"grpc": 8881,
	}

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
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

func newThanosReceiveService(
	env e2e.Environment,
	name, replicaLabel, defaultTenantID string,
	hashringsContainerPath string,
) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"http":         10902,
		"grpc":         10901,
		"remote_write": 19291,
	}

	args := e2e.BuildArgs(map[string]string{
		"--receive.hashrings-file":    hashringsContainerPath,
		"--receive.local-endpoint":    "0.0.0.0:10901",
		"--label":                     replicaLabel,
		"--receive.default-tenant-id": defaultTenantID,
		"--grpc-address":              "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--http-address":              "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--remote-write.address":      "0.0.0.0:19291",
		"--log.level":                 "debug", // TODO: Log levels? Which to use where?
		"--tsdb.path":                 "/tmp",
	})

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:     thanosImage,
			Command:   e2e.NewCommand("receive", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/-/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

func newThanosQueryService(
	env e2e.Environment,
	name string,
	storeAddress string,
) *e2e.InstrumentedRunnable {
	ports := map[string]int{
		"http": 9091,
		"grpc": 10911,
	}

	args := e2e.BuildArgs(map[string]string{
		"--grpc-address": "0.0.0.0:" + strconv.Itoa(ports["grpc"]),
		"--http-address": "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--store":        storeAddress,
		"--log.level":    "error", // TODO: Log levels? Which to use where?
	})

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:     thanosImage,
			Command:   e2e.NewCommand("query", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/-/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

func newLokiService(env e2e.Environment, name string, configContainerPath string) *e2e.InstrumentedRunnable {
	ports := map[string]int{"http": 3100}

	fmt.Println(configContainerPath)

	args := e2e.BuildArgs(map[string]string{
		"-config.file": configContainerPath,
		"-target":      "all",
		"-log.level":   "error", // TODO: Log levels? Which to use where?
	})

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:   lokiImage,
			Command: e2e.NewCommandWithoutEntrypoint("loki", args...),
			// TODO: Remove 503, we should wait until 200?
			Readiness: e2e.NewHTTPReadinessProbe("http", "/ready", 200, 503),
			User:      strconv.Itoa(os.Getuid()),
			// WaitReadyBackoff: &backoff.Config{
			// 	Min: 15 * time.Second,
			// 	Max: 15 * time.Second,
			// },
		},
	)
}

func newOPAService(env e2e.Environment, name string, containerConfigDir string) *e2e.InstrumentedRunnable {
	ports := map[string]int{"http": 8181}

	args := e2e.BuildArgs(map[string]string{
		"--server":         "",
		containerConfigDir: "",
		"--ignore":         "*.json",
	})

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:     opaImage,
			Command:   e2e.NewCommand("run", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http", "/health", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	)
}

// TODO: Make into fuctional options?
func newObservatoriumAPIService(
	env e2e.Environment,
	name string,
	logsReadEndpoint, logsTailEndpoint, logsWriteEndpoint string,
	metricsReadEndpoint, metricsWriteEndpoint string,
	rbacConfigPath, tenantsConfigPath, certsPath string,
	rateLimiterGRPCAddress string,
) (*e2e.InstrumentedRunnable, error) {
	ports := map[string]int{
		"https":         8443,
		"http-internal": 8448,
	}

	args := e2e.BuildArgs(map[string]string{
		"--web.listen":                      ":" + strconv.Itoa(ports["https"]),
		"--web.internal.listen":             ":" + strconv.Itoa(ports["http-internal"]),
		"--web.healthchecks.url":            "https://127.0.0.1:8443",
		"--tls.server.cert-file":            filepath.Join(certsPath, "server.pem"),
		"--tls.server.key-file":             filepath.Join(certsPath, "server.key"),
		"--tls.healthchecks.server-ca-file": filepath.Join(certsPath, "ca.pem"),
		// TODO: Make conditional based on if provided
		// "--logs.read.endpoint":              logsReadEndpoint,
		// "--logs.tail.endpoint":              logsTailEndpoint,
		// "--logs.write.endpoint":    logsWriteEndpoint,
		"--metrics.read.endpoint":  "http://" + metricsReadEndpoint,
		"--metrics.write.endpoint": "http://" + metricsWriteEndpoint,
		"--rbac.config":            rbacConfigPath,
		"--tenants.config":         tenantsConfigPath,
		"--log.level":              "debug",
	})

	if rateLimiterGRPCAddress != "" {
		args = append(args, "--middleware.rate-limiter.grpc-address="+rateLimiterGRPCAddress)
	}

	return e2e.NewInstrumentedRunnable(env, name, ports, "http-internal").Init(
		e2e.StartOptions{
			Image:     apiImage,
			Command:   e2e.NewCommandWithoutEntrypoint("observatorium-api", args...),
			Readiness: e2e.NewHTTPReadinessProbe("http-internal", "/ready", 200, 200),
			User:      strconv.Itoa(os.Getuid()),
		},
	), nil
}

func newUpService(
	env e2e.Environment,
	name string,
	endpointType string,
	readEndpoint, writeEndpoint string,
	containerCertsDir string,
	token string,
) (*e2e.InstrumentedRunnable, error) {
	ports := map[string]int{
		"http": 8888,
	}

	args := e2e.BuildArgs(map[string]string{
		"--listen":         "0.0.0.0:" + strconv.Itoa(ports["http"]),
		"--endpoint-type":  endpointType,
		"--tls-ca-file":    filepath.Join(containerCertsDir, "ca.pem"),
		"--endpoint-read":  readEndpoint,
		"--endpoint-write": writeEndpoint,
		"--period":         "500ms",
		"--threshold":      "1",
		"--latency":        "10s",
		"--duration":       "0",
		"--log.level":      "debug",
		"--name":           "observatorium_write",
		"--labels":         "_id=\"test\"",
		"--token":          token,
	})

	return e2e.NewInstrumentedRunnable(env, name, ports, "http").Init(
		e2e.StartOptions{
			Image:   upImage,
			Command: e2e.NewCommandWithoutEntrypoint("up", args...),
			// Readiness: e2e.NewHTTPReadinessProbe("http", "/", 200, 200),
			User: strconv.Itoa(os.Getuid()),
		},
	), nil
}
