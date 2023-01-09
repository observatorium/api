//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/efficientgo/core/backoff"
	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
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

	//nolint:lll
	// queriedV3Trace is traceJSON returned through Jaeger's V3 API.
	queriedV3Trace = `{"result":{"resourceSpans":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"testHost"}}]},"instrumentationLibrarySpans":[{"instrumentationLibrary":{},"spans":[{"traceId":"W47/95gDgQPSabYzgT/GDA==","spanId":"7uGbfsPBsXM=","parentSpanId":"AAAAAAAAAAA=","name":"testSpan","kind":"SPAN_KIND_INTERNAL","startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","attributes":[{"key":"attr1","value":{"intValue":"55"}},{"key":"internal.span.format","value":{"stringValue":"proto"}}]}]}]}]}}`

	//nolint:lll
	// queriedV2Trace is traceJSON returned through Jaeger's V2 API.
	queriedV2Trace = `{"data":[{"traceID":"5b8efff798038103d269b633813fc60c","spans":[{"traceID":"5b8efff798038103d269b633813fc60c","spanID":"eee19b7ec3c1b173","operationName":"testSpan","references":[],"startTime":1544712660000000,"duration":1000000,"tags":[{"key":"attr1","type":"int64","value":55},{"key":"internal.span.format","type":"string","value":"proto"}],"logs":[],"processID":"p1","warnings":null}],"processes":{"p1":{"serviceName":"","tags":[{"key":"host.name","type":"string","value":"testHost"}]}},"warnings":null}],"total":0,"limit":0,"offset":0,"errors":null}`

	// queriedV2Dependencies is dependencies JSON returned through Jaeger's V2 API.
	queriedV2Dependencies = `{"data":[],"total":0,"limit":0,"offset":0,"errors":null}`
)

func TestTracesExport(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envTracesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, traces, e)
	_, token, _ := startBaseServices(t, e, traces)
	internalOtlpEndpoint, httpExternalQueryEndpoint, httpInternalQueryEndpoint := startServicesForTraces(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		withOtelTraceEndpoint(internalOtlpEndpoint),
		withJaegerEndpoint("http://"+httpInternalQueryEndpoint),

		// This test doesn't actually write logs, but we need
		// this because Observatorium currently MUST see a logs or metrics endpoints.
		withLogsEndpoints("http://localhost:8080"),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("write-then-query-single-trace", func(t *testing.T) {

		createOtelForwardingCollectorConfigYAML(t, e,
			api.InternalEndpoint("grpc"),
			token)

		otel := e.Runnable("otel-fwd-collector").
			WithPorts(
				map[string]int{
					"http":         4318,
					"grpc":         4317,
					"health_check": 13133,
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
				Readiness: e2e.NewHTTPReadinessProbe(
					"health_check",
					"/health/status",
					200,
					200,
				),
			})

		testutil.Ok(t, e2e.StartAndWaitReady(otel))

		// Send trace insecurly to forwarding OTel collector for forwarding through Observatorium
		// (This code could be refactored to observatorium/up, the test client).

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

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "{}")

		testutil.Equals(t, http.StatusOK, response.StatusCode)

		returnedTrace := queryForTraceDirectV3(t,
			httpExternalQueryEndpoint, "5B8EFFF798038103D269B633813FC60C")
		assertResponse(t, returnedTrace, queriedV3Trace)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		httpObservatoriumQueryEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/api", api.Endpoint("https"))
		httpObservatoriumQueryTraceEndpoint := fmt.Sprintf("%s/traces", httpObservatoriumQueryEndpoint)
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".
		returnedTrace, _ = queryForTraceV2(t, "valid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		_, returnedStatus := queryForTraceV2(t, "invalid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer invalid-token"), 500)
		testutil.Equals(t, returnedStatus, 500)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		_, returnedStatus = queryJaeger(t, "Observatorium services v2 query",
			fmt.Sprintf("%s/services", httpObservatoriumQueryEndpoint),
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		// We don't compare the JSON, as it can differ
		// slightly depending on timing and retries.
		testutil.Equals(t, returnedStatus, 200)

		returnedDependencies, _ := queryJaeger(t, "Observatorium dependencies v2 query",
			fmt.Sprintf("%s/dependencies", httpObservatoriumQueryEndpoint),
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedDependencies, queriedV2Dependencies)
	})
}

func queryForTraceDirectV3(t *testing.T, httpQueryEndpoint, traceID string) string {
	t.Helper()

	request, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s/api/v3/traces/%s", httpQueryEndpoint, traceID),
		nil)
	testutil.Ok(t, err)

	s, _ := requestWithRetry(t, "jaeger V3 get trace", &http.Client{}, request, http.StatusOK)
	return s
}

func queryForTraceV2(t *testing.T, testLabel, httpQueryURL, traceID string, insecureSkipVerify bool, authHeader string,
	expectedResponse int) (string, int) {
	t.Helper()
	return queryJaeger(t, testLabel, fmt.Sprintf("%s/%s", httpQueryURL, traceID),
		insecureSkipVerify, authHeader, expectedResponse)
}

func queryJaeger(t *testing.T, testLabel, httpQueryURL string, insecureSkipVerify bool, authHeader string,
	expectedResponse int) (string, int) {
	t.Helper()

	request, err := http.NewRequest(
		"GET",
		httpQueryURL,
		nil)
	testutil.Ok(t, err)
	request.Header.Set("authorization", authHeader)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		},
	}

	return requestWithRetry(t, testLabel, client, request, expectedResponse)
}

func requestWithRetry(t *testing.T, testLabel string, client *http.Client, request *http.Request, expectedResponse int) (string, int) {
	t.Helper()

	// Read to verify the trace is there.  Retry in case
	// there is a short delay with trace storage.
	ctx := context.Background()
	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 10,
	})
	for b.Reset(); b.Ongoing(); {
		response, err := client.Do(request)
		// Retry if we have a connection problem (timeout, etc)
		if err != nil {
			b.Wait()
			continue
		}

		// Jaeger might give a 404 or 500 before the trace is there.  Retry.
		if response.StatusCode != expectedResponse {
			b.Wait()
			continue
		}

		// We got a 200 response.
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		return string(body), response.StatusCode
	}

	testutil.Assert(t, false, fmt.Sprintf("%s: HTTP %d response not received within time limit", testLabel, expectedResponse))
	return "", -1
}

func TestTracesTemplateQuery(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envTracesTemplateName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, tracesTemplate, e)
	_, token, _ := startBaseServices(t, e, tracesTemplate)
	internalOtlpEndpoint, httpExternalQueryEndpoint, httpInternalQueryEndpoint := startServicesForTraces(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		// Note that we don't include `{tenant}`, because we can't easily do this with DNS on Docker.
		withOtelTraceEndpoint(internalOtlpEndpoint),
		withExperimentalJaegerTemplateEndpoint("http://"+httpInternalQueryEndpoint),

		// This test doesn't actually write logs, but we need
		// this because Observatorium currently MUST see a logs or metrics endpoints.
		withLogsEndpoints("http://localhost:8080"),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("write-then-template-query-single-trace", func(t *testing.T) {
		createOtelForwardingCollectorConfigYAML(t, e,
			api.InternalEndpoint("grpc"),
			token)

		otel := e.Runnable("otel-fwd-collector").
			WithPorts(
				map[string]int{
					"http":         4318,
					"grpc":         4317,
					"health_check": 13133,
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
				Readiness: e2e.NewHTTPReadinessProbe(
					"health_check",
					"/health/status",
					200,
					200,
				),
			})

		testutil.Ok(t, e2e.StartAndWaitReady(otel))

		// Send trace insecurly to forwarding OTel collector for forwarding through Observatorium
		// (This code could be refactored to observatorium/up, the test client).

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

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "{}")

		testutil.Equals(t, http.StatusOK, response.StatusCode)

		returnedTrace := queryForTraceDirectV3(t,
			httpExternalQueryEndpoint, "5B8EFFF798038103D269B633813FC60C")
		assertResponse(t, returnedTrace, queriedV3Trace)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		httpObservatoriumQueryEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/api", api.Endpoint("https"))
		httpObservatoriumQueryTraceEndpoint := fmt.Sprintf("%s/traces", httpObservatoriumQueryEndpoint)
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".
		returnedTrace, _ = queryForTraceV2(t, "valid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		_, returnedStatus := queryForTraceV2(t, "invalid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer invalid-token"), 500)
		testutil.Equals(t, returnedStatus, 500)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace)

		_, returnedStatus = queryJaeger(t, "Observatorium services v2 query",
			fmt.Sprintf("%s/services", httpObservatoriumQueryEndpoint),
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		// We don't compare the JSON, as it can differ
		// slightly depending on timing and retries.
		testutil.Equals(t, returnedStatus, 200)

		returnedDependencies, _ := queryJaeger(t, "Observatorium dependencies v2 query",
			fmt.Sprintf("%s/dependencies", httpObservatoriumQueryEndpoint),
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedDependencies, queriedV2Dependencies)
	})
}
