//go:build integration
// +build integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

const (
	// Note that if the forwarding collector uses OIDC flow instead of hard-coding
	// the bearer token we would need
	// "otel/opentelemetry-collector-contrib:0.45.0" instead.
	otelFwdCollectorImage = "otel/opentelemetry-collector:0.45.0"

	// OTel trace collector that receives in HTTP w/o security, but exports in gRPC with security.
	otelForwardingConfig = `
receivers:
    otlp:
      protocols:
        http:
            endpoint: 0.0.0.0:4318
        grpc:
            endpoint: 0.0.0.0:4317

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
	_, token, _ := startBaseServices(t, e, traces)
	internalOtlpEndpoint, httpQueryEndpoint := startServicesForTraces(t, e)

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
			"{{OBS_GRPC_ENDPOINT}}",
			api.InternalEndpoint("grpc"), -1)
		forwardingConfig = strings.Replace(forwardingConfig,
			"{{DEX_TOKEN}}",
			token, -1)

		otelFile, err := ioutil.TempFile(e.SharedDir(), "fwd-coll***.yaml")
		testutil.Ok(t, err)

		err = os.Chmod(otelFile.Name(), 0644)
		testutil.Ok(t, err)

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
				Image:   otelFwdCollectorImage,
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

		// Read from Jaeger to verify the trace is there.  Retry in case
		// there is a short delay with trace storage.
		ctx := context.Background()
		b := backoff.New(ctx, backoff.Config{
			Min:        500 * time.Millisecond,
			Max:        5 * time.Second,
			MaxRetries: 10,
		})
		for b.Reset(); b.Ongoing(); {
			response, err = client.Do(request)
			// Retry if we have a connection problem (timeout, etc)
			if err != nil {
				b.Wait()
				continue
			}

			// Jaeger might give a 404 or 500 before the trace is there.  Retry.
			if response.StatusCode != http.StatusOK {
				b.Wait()
				continue
			}

			// We got a 200 response.  Verify the trace appears as expected.
			defer response.Body.Close()

			body, err = ioutil.ReadAll(response.Body)
			testutil.Ok(t, err)

			bodyStr = string(body)
			//nolint:lll
			assertResponse(t, bodyStr, `{"result":{"resourceSpans":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"testHost"}}]},"instrumentationLibrarySpans":[{"instrumentationLibrary":{},"spans":[{"traceId":"W47/95gDgQPSabYzgT/GDA==","spanId":"7uGbfsPBsXM=","parentSpanId":"AAAAAAAAAAA=","name":"testSpan","kind":"SPAN_KIND_INTERNAL","startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","attributes":[{"key":"attr1","value":{"intValue":"55"}},{"key":"internal.span.format","value":{"stringValue":"proto"}}]}]}]}]}}`)

			break
		}
	})
}
