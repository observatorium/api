//go:build interactive
// +build interactive

// (TODO switch above back to experimentalintegration)

package e2e

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

// OTel trace collector that receives in HTTP w/o security, but exports in gRPC with security.
const otelForwardingConfig = `
receivers:
    otlp:
      protocols:
        http:
            endpoint: 0.0.0.0:4318
        grpc:
            endpoint: 0.0.0.0:4317

extensions:
    oauth2client:
      client_id: {{OBS_CLIENT_ID}}
      client_secret: {{OBS_CLIENT_SECRET}}
      token_url: {{OIDC_TOKEN_URL}}
  
exporters:
    logging:
      logLevel: debug
    otlp:
      endpoint: {{OBS_GRPC_ENDPOINT}}
      auth:
        authenticator: oauth2client
      tls:
        insecure_skip_verify: true
      headers:
        x-tenant: test-oidc
      
service:
    telemetry:
      metrics:
        address: localhost:8889
    extensions: [oauth2client]
    pipelines:
      traces:
        receivers: [otlp]
        exporters: [logging,otlp]
`

func TestTracesExport(t *testing.T) {
	t.Parallel()

	e, err := e2e.NewDockerEnvironment(envTracesName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, traces, e)
	dex, token, _ := startBaseServices(t, e, traces)
	otlpEndpoint, httpQueryEndpoint := startServicesForTraces(t, e)

	oidcEndpoint := dex.Endpoint("https")
	tokenUrl := fmt.Sprintf("https://%s/dex/token", oidcEndpoint)
	clientId := "test"                         // TODO Refactor this to a const shared with _helpers.go_
	clientSecret := "ZXhhbXBsZS1hcHAtc2VjcmV0" // TODO Refactor this to a const shared with _helpers.go_

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint("localhost:8317"),
		withOtelTraceEndpoint(otlpEndpoint),

		// This test doesn't actually write logs, but we need
		// this because Observatorium currently MUST see a logs or metrics endpoints
		withLogsEndpoints("http://localhost:8080"),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	// In theory this can be checked at compile time, but many editors will screw this up
	// and the test prevents confusion.
	if strings.ContainsRune(otelForwardingConfig, '\t') {
		t.Errorf("Tab in the YAML")
	}

	forwardingConfig := strings.Replace(otelForwardingConfig,
		"{{OBS_CLIENT_ID}}",
		clientId, -1)
	forwardingConfig = strings.Replace(forwardingConfig,
		"{{OBS_CLIENT_SECRET}}",
		clientSecret, -1)
	forwardingConfig = strings.Replace(forwardingConfig,
		"{{OIDC_TOKEN_URL}}",
		tokenUrl, -1)
	forwardingConfig = strings.Replace(forwardingConfig,
		"{{OBS_GRPC_ENDPOINT}}",
		api.Endpoint("grpc"), -1)

	dir, err := ioutil.TempDir(".", "observatorium-tests")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// @@@ ecs TODO RESTORE defer os.RemoveAll(dir)

	otelFile, err := ioutil.TempFile(dir, "fwd-coll.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// @@@ ecs TODO RESTORE defer os.Remove(otelFile.Name())

	_, err = otelFile.Write([]byte(forwardingConfig))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// otelFile.Name() will give relative pathname to temp file.  Docker will complain with
	// "If you intended to pass a host directory, use absolute path.""
	otelFileName, err := filepath.Abs(otelFile.Name())
	if err != nil {
		t.Fatalf("unexpected Abs() error: %s", err)
	}

	otel := e.Runnable("otel-fwd-coll").
		WithPorts(
			map[string]int{
				"http": 4318,
				"grpc": 4317,
			}).
		Init(e2e.StartOptions{
			Image:   "otel/opentelemetry-collector-contrib:0.45.0",
			Volumes: []string{fmt.Sprintf("%s:/conf/collector.yaml", otelFileName)},
			Command: e2e.Command{
				Args: []string{"--config=/conf/collector.yaml"},
			},
		})

	testutil.Ok(t, e2e.StartAndWaitReady(otel))

	// TODO Actually test writing traces
	// TODO Actually test reading traces

	// TODO Remove interactive stuff
	fmt.Printf("\n")
	fmt.Printf("You're all set up!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Observatorium API on host machine:                %s\n", api.Endpoint("https"))
	fmt.Printf("Observatorium internal server on host machine:    %s\n", api.Endpoint("http-internal"))
	fmt.Printf("Observatorium gRPC API on host machine:           %s\n", api.Endpoint("grpc"))
	fmt.Printf("Jaeger Query on host machine (HTTP):              %s\n", httpQueryEndpoint)
	fmt.Printf("OTel Collector on host machine (GRPC):            %s\n", otlpEndpoint)
	fmt.Printf("OTel Forwarding Collector on host machine (HTTP): %s\n", otel.Endpoint("http"))
	fmt.Printf("OTel Forwarding Collector on host machine (gRPC): %s\n", otel.Endpoint("grpc"))
	fmt.Printf("API Token:                                        %s\n\n", token)

	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
}
