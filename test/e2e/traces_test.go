//go:build integration
// +build integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

const (
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

		createOtelForwardingCollectorConfigYAML(t, e,
			api.InternalEndpoint("grpc"),
			token)

		otel := e.Runnable("otel-fwd-coll").
			WithPorts(
				map[string]int{
					"http": 4318,
					"grpc": 4317,
				}).
			Init(e2e.StartOptions{
				Image: otelFwdCollectorImage,
				Volumes: []string{
					fmt.Sprintf("%s:/conf/forwarding-collector.yaml",
						filepath.Join(filepath.Join(e.SharedDir(), configSharedDir, "forwarding-collector.yaml"))),
				},
				Command: e2e.Command{
					Args: []string{"--config=/conf/forwarding-collector.yaml"},
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
