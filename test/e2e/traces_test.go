//go:build experimentalintegration
// +build experimentalintegration

package e2e

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

// OTel trace collector that receives in HTTP w/o security, but exports in gRPC with security.
const (
	otelForwardingConfig = `
receivers:
    otlp:
      protocols:
        http:
            endpoint: 0.0.0.0:4318
        grpc:
            endpoint: 0.0.0.0:4317

# extensions:
#     oauth2client:
#       client_id: {{OBS_CLIENT_ID}}
#       client_secret: {{OBS_CLIENT_SECRET}}
#       token_url: {{OIDC_TOKEN_URL}}
#      # The test dex's certs are signed for localhost, not 'e2e_traces_read_export-dex'
#      tls:
#        insecure_skip_verify: true
  
exporters:
    logging:
      logLevel: debug
    otlp:
      endpoint: {{OBS_GRPC_ENDPOINT}}
      # auth:
      #   authenticator: oauth2client
      tls:
        insecure_skip_verify: true
      compression: none
      headers:
        x-tenant: test-oidc
        # (Use hard-coded auth header, because this forwarding collector
        # is unable to do OIDC password grant.)
        authorization: bearer {{DEX_TOKEN}}

service:
    telemetry:
      metrics:
        address: localhost:8889
    # extensions: [oauth2client]
    pipelines:
      traces:
        receivers: [otlp]
        exporters: [logging,otlp]
`
	traceJSON = `
{
	"resource_spans": [
	{
		"resource": {
		"attributes": [
			{
			"key": "host.name",
			"value": { "stringValue": "testHost" }
			}
		]
		},
		"instrumentation_library_spans": [
		{
			"spans": [
			{
				"trace_id": "5B8EFFF798038103D269B633813FC60C",
				"span_id": "EEE19B7EC3C1B173",
				"name": "testSpan",
				"start_time_unix_nano": 1544712660000000000,
				"end_time_unix_nano": 1544712661000000000,
				"attributes": [
				{
					"key": "attr1",
					"value": { "intValue": 55 }
				}
				]
			}
			]
		}
		]
	}
	]
}`
)

func TestTracesExport(t *testing.T) {
	t.Parallel()

	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(otelForwardingConfig, '\t') {
		t.Fatalf("Tab in the YAML")
	}

	e, err := e2e.NewDockerEnvironment(envTracesName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, traces, e)
	dex, token, _ := startBaseServices(t, e, traces)
	internalOtlpEndpoint, httpQueryEndpoint := startServicesForTraces(t, e)

	// oidcEndpoint := dex.Endpoint("https")
	oidcEndpoint := dex.InternalEndpoint("https")
	tokenUrl := fmt.Sprintf("https://%s/dex/token", oidcEndpoint)
	clientId := "test"                         // TODO Refactor this to a const shared with _helpers.go_
	clientSecret := "ZXhhbXBsZS1hcHAtc2VjcmV0" // TODO Refactor this to a const shared with _helpers.go_

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		withOtelTraceEndpoint(internalOtlpEndpoint),

		// This test doesn't actually write logs, but we need
		// this because Observatorium currently MUST see a logs or metrics endpoints
		withLogsEndpoints("http://localhost:8080"),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("write-then-query-single-trace", func(t *testing.T) {

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
			api.InternalEndpoint("grpc"), -1)
		forwardingConfig = strings.Replace(forwardingConfig,
			"{{DEX_TOKEN}}",
			token, -1)

		otelFile, err := ioutil.TempFile(e.SharedDir(), "fwd-coll.yaml")
		testutil.Ok(t, err)

		defer os.Remove(otelFile.Name())

		_, err = otelFile.Write([]byte(forwardingConfig))
		testutil.Ok(t, err)

		// otelFile.Name() will give relative pathname to temp file.  Docker will complain with
		// "If you intended to pass a host directory, use absolute path.""
		otelFileName, err := filepath.Abs(otelFile.Name())
		testutil.Ok(t, err)

		otel := e.Runnable("otel-fwd-coll").
			WithPorts(
				map[string]int{
					"http": 4318,
					"grpc": 4317,
				}).
			Init(e2e.StartOptions{
				// Note that if the forwarding collector was OIDC flow we would need
				// "otel/opentelemetry-collector-contrib:0.45.0" instead.
				Image:   "otel/opentelemetry-collector:0.45.0",
				Volumes: []string{fmt.Sprintf("%s:/conf/collector.yaml", otelFileName)},
				Command: e2e.Command{
					Args: []string{"--config=/conf/collector.yaml"},
				},
			})

		testutil.Ok(t, e2e.StartAndWaitReady(otel))

		// Send trace insecurly to forwarding OTel collector for forwarding through Observatorium
		// (This code could be refactored to observatorium/up, the test client)

		client := &http.Client{}
		request, err := http.NewRequest(
			"POST",
			fmt.Sprintf("http://%s/v1/traces", otel.Endpoint("http")),
			bytes.NewBuffer([]byte(traceJSON)))
		testutil.Ok(t, err)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "{}")

		testutil.Equals(t, http.StatusOK, response.StatusCode)

		request, err = http.NewRequest(
			"GET",
			fmt.Sprintf("http://%s/api/v3/traces/%s", httpQueryEndpoint, "5B8EFFF798038103D269B633813FC60C"),
			nil)
		testutil.Ok(t, err)

		// Note that we don't wait for the trace to be committed to storage.
		// (If we were using a buffered Jaeger storage backend we would
		// not give up on the first fetch attempt.)
		response, err = client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		body, err = ioutil.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr = string(body)
		//nolint:lll
		assertResponse(t, bodyStr, `{"result":{"resourceSpans":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"testHost"}}]},"instrumentationLibrarySpans":[{"instrumentationLibrary":{},"spans":[{"traceId":"W47/95gDgQPSabYzgT/GDA==","spanId":"7uGbfsPBsXM=","parentSpanId":"AAAAAAAAAAA=","name":"testSpan","kind":"SPAN_KIND_INTERNAL","startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","attributes":[{"key":"attr1","value":{"intValue":"55"}},{"key":"internal.span.format","value":{"stringValue":"proto"}}]}]}]}]}}`)

		testutil.Equals(t, http.StatusOK, response.StatusCode)

		// Uncomment for interactive test
		/*
			fmt.Printf("\n")
			fmt.Printf("You're all set up!\n")
			fmt.Printf("========================================\n")
			fmt.Printf("Observatorium API on host machine:                %s\n", api.Endpoint("https"))
			fmt.Printf("Observatorium internal server on host machine:    %s\n", api.Endpoint("http-internal"))
			fmt.Printf("Observatorium gRPC API on host machine:           %s\n", api.Endpoint("grpc"))
			fmt.Printf("Jaeger Query on host machine (HTTP):              %s\n", httpQueryEndpoint)
			fmt.Printf("OTel Forwarding Collector on host machine (HTTP): %s\n", otel.Endpoint("http"))
			fmt.Printf("OTel Forwarding Collector on host machine (gRPC): %s\n", otel.Endpoint("grpc"))
			fmt.Printf("API Token:                                        %s\n\n", token)

			testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
		*/
	})
}
