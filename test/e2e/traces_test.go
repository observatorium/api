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
	traceJSON5B = `
{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {
            "key": "service.name",
            "value": {
              "stringValue": "my.service"
            }
          }
        ]
      },
      "scopeSpans": [
        {
          "scope": {
            "name": "my.library",
            "version": "1.0.0",
            "attributes": [
              {
                "key": "my.scope.attribute",
                "value": {
                  "stringValue": "some scope attribute"
                }
              }
            ]
          },
          "spans": [
            {
              "traceId": "5B8EFFF798038103D269B633813FC60C",
              "spanId": "EEE19B7EC3C1B174",
              "parentSpanId": "EEE19B7EC3C1B173",
              "name": "I'm a server span",
              "startTimeUnixNano": "1544712660000000000",
              "endTimeUnixNano": "1544712661000000000",
              "kind": 2,
              "attributes": [
                {
                  "key": "my.span.attr",
                  "value": {
                    "stringValue": "some value"
                  }
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}`

	traceJSON6B = `
{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {
            "key": "service.name",
            "value": {
              "stringValue": "my.service"
            }
          }
        ]
      },
      "scopeSpans": [
        {
          "scope": {
            "name": "my.library",
            "version": "1.0.0",
            "attributes": [
              {
                "key": "my.scope.attribute",
                "value": {
                  "stringValue": "some scope attribute"
                }
              }
            ]
          },
          "spans": [
            {
              "traceId": "6B8EFFF798038103D269B633813FC60C",
              "spanId": "EEE19B7EC3C1B174",
              "parentSpanId": "EEE19B7EC3C1B173",
              "name": "I'm a server span",
              "startTimeUnixNano": "1544712660000000000",
              "endTimeUnixNano": "1544712661000000000",
              "kind": 2,
              "attributes": [
                {
                  "key": "my.span.attr",
                  "value": {
                    "stringValue": "some value"
                  }
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
	queriedV3Trace5B = `{"result":{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"my.service"}}]},"scopeSpans":[{"scope":{"name":"my.library","version":"1.0.0"},"spans":[{"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","parentSpanId":"eee19b7ec3c1b173","name":"I'm a server span","kind":2,"startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","attributes":[{"key":"my.span.attr","value":{"stringValue":"some value"}},{"key":"internal.span.format","value":{"stringValue":"otlp"}}],"status":{}}]}]}]}}`

	//nolint:lll
	// queriedV2Trace is traceJSON returned through Jaeger's V2 API.
	queriedV2Trace5B = `{"data":[{"traceID":"5b8efff798038103d269b633813fc60c","spans":[{"traceID":"5b8efff798038103d269b633813fc60c","spanID":"eee19b7ec3c1b174","operationName":"I'm a server span","references":[{"refType":"CHILD_OF","traceID":"5b8efff798038103d269b633813fc60c","spanID":"eee19b7ec3c1b173"}],"startTime":1544712660000000,"duration":1000000,"tags":[{"key":"my.span.attr","type":"string","value":"some value"},{"key":"span.kind","type":"string","value":"server"},{"key":"internal.span.format","type":"string","value":"otlp"}],"logs":[],"processID":"p1","warnings":["invalid parent span IDs=eee19b7ec3c1b173; skipping clock skew adjustment"]}],"processes":{"p1":{"serviceName":"my.service","tags":[{"key":"otel.library.name","type":"string","value":"my.library"},{"key":"otel.library.version","type":"string","value":"1.0.0"}]}},"warnings":null}],"total":0,"limit":0,"offset":0,"errors":null}`

	//nolint:lll
	// queriedV2Trace is traceJSON returned through Jaeger's V2 API.
	queriedV2Trace6B = `{"data":[{"traceID":"6b8efff798038103d269b633813fc60c","spans":[{"traceID":"6b8efff798038103d269b633813fc60c","spanID":"eee19b7ec3c1b174","operationName":"I'm a server span","references":[{"refType":"CHILD_OF","traceID":"6b8efff798038103d269b633813fc60c","spanID":"eee19b7ec3c1b173"}],"startTime":1544712660000000,"duration":1000000,"tags":[{"key":"my.span.attr","type":"string","value":"some value"},{"key":"span.kind","type":"string","value":"server"},{"key":"internal.span.format","type":"string","value":"otlp"}],"logs":[],"processID":"p1","warnings":["invalid parent span IDs=eee19b7ec3c1b173; skipping clock skew adjustment"]}],"processes":{"p1":{"serviceName":"my.service","tags":[{"key":"otel.library.name","type":"string","value":"my.library"},{"key":"otel.library.version","type":"string","value":"1.0.0"}]}},"warnings":null}],"total":0,"limit":0,"offset":0,"errors":null}`

	// queriedV2Dependencies is dependencies JSON returned through Jaeger's V2 API.
	queriedV2Dependencies = `{"data":[],"total":0,"limit":0,"offset":0,"errors":null}`

	tempoTraceResponse5B = `{"batches":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"my.service"}}]},"scopeSpans":[{"scope":{"name":"my.library","version":"1.0.0","attributes":[{"key":"my.scope.attribute","value":{"stringValue":"some scope attribute"}}]},"spans":[{"traceId":"W47/95gDgQPSabYzgT/GDA==","spanId":"7uGbfsPBsXQ=","parentSpanId":"7uGbfsPBsXM=","name":"I'm a server span","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","attributes":[{"key":"my.span.attr","value":{"stringValue":"some value"}}],"status":{}}]}]}]}`
)

func TestTracesExport(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envTracesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, traces, e)
	_, token, _ := startBaseServices(t, e, traces)
	internalOTLPGRPCEndpoint, internalOTLPHTTPEndpoint, httpExternalQueryEndpoint, httpInternalQueryEndpoint := startServicesForTraces(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		withOTLPGRPCTraceEndpoint(internalOTLPGRPCEndpoint),
		withOTLPHTTPTraceEndpoint("http://"+internalOTLPHTTPEndpoint),
		withJaegerEndpoint("http://"+httpInternalQueryEndpoint),

		// This test doesn't actually write logs, but we need
		// this because Observatorium currently MUST see a logs or metrics endpoints.
		withLogsEndpoints("http://localhost:8080"),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("write-grpc-then-query-single-trace", func(t *testing.T) {
		createOtelForwardingCollectorConfigYAML(t, e,
			api.InternalEndpoint("grpc"),
			token)

		otel := e.Runnable("otel-fwd-collector").
			WithPorts(
				map[string]int{
					"http":         4318,
					"grpc":         4317,
					"health_check": 13133,
					"telemetry":    8889,
				}).
			Init(e2e.StartOptions{
				Image: otelCollectorImage,
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
			bytes.NewBuffer([]byte(traceJSON5B)))
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
		assertResponse(t, returnedTrace, queriedV3Trace5B)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

		httpObservatoriumQueryEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/api", api.Endpoint("https"))
		httpObservatoriumQueryTraceEndpoint := fmt.Sprintf("%s/traces", httpObservatoriumQueryEndpoint)
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".
		returnedTrace, _ = queryForTraceV2(t, "valid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

		_, returnedStatus := queryForTraceV2(t, "invalid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer invalid-token"), 500)
		testutil.Equals(t, returnedStatus, 500)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

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

		returnedMetrics, _ := queryJaeger(t, "Observatorium Jaeger metrics query",
			fmt.Sprintf("%s/metrics/calls?service=doesnotexist", httpObservatoriumQueryEndpoint),
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		testutil.Equals(t, `{"name":"service_call_rate","type":"GAUGE","help":"calls/sec, grouped by service","metrics":[]}`, returnedMetrics)
	})

	t.Run("write-http-then-query-single-trace", func(t *testing.T) {
		tlsClientConfig := getTLSClientConfig(t, e)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsClientConfig}}
		request, err := http.NewRequest(
			"POST",
			fmt.Sprintf("https://%s/api/traces/v1/test-oidc/v1/traces", api.Endpoint("https")),
			bytes.NewBuffer([]byte(traceJSON6B)))
		testutil.Ok(t, err)
		request.Header.Set("x-tenant", "test-oidc")
		request.Header.Set("authorization", fmt.Sprintf("bearer %s", token))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "{\"partialSuccess\":{}}")
		testutil.Equals(t, http.StatusOK, response.StatusCode)

		httpObservatoriumQueryEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/api", api.Endpoint("https"))
		httpObservatoriumQueryTraceEndpoint := fmt.Sprintf("%s/traces", httpObservatoriumQueryEndpoint)
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".
		returnedTrace, _ := queryForTraceV2(t, "valid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "6B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace6B)
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

func queryForTraceTempo(t *testing.T, testLabel, httpQueryURL, traceID string, insecureSkipVerify bool, authHeader string,
	expectedResponse int) (string, int) {
	t.Helper()
	request, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/traces/%s", httpQueryURL, traceID),
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
	internalOTLPGRPCEndpoint, _, httpExternalQueryEndpoint, httpInternalQueryEndpoint := startServicesForTraces(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		// Note that we don't include `{tenant}`, because we can't easily do this with DNS on Docker.
		withOTLPGRPCTraceEndpoint(internalOTLPGRPCEndpoint),
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
				Image: otelCollectorImage,
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
			bytes.NewBuffer([]byte(traceJSON5B)))
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
		assertResponse(t, returnedTrace, queriedV3Trace5B)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

		httpObservatoriumQueryEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/api", api.Endpoint("https"))
		httpObservatoriumQueryTraceEndpoint := fmt.Sprintf("%s/traces", httpObservatoriumQueryEndpoint)
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".
		returnedTrace, _ = queryForTraceV2(t, "valid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

		_, returnedStatus := queryForTraceV2(t, "invalid Observatorium trace v2 query",
			httpObservatoriumQueryTraceEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer invalid-token"), 500)
		testutil.Equals(t, returnedStatus, 500)

		returnedTrace, _ = queryForTraceV2(t, "direct Jaeger v2 query",
			fmt.Sprintf("http://%s/api/traces", httpExternalQueryEndpoint), "5B8EFFF798038103D269B633813FC60C",
			false, "", http.StatusOK)
		assertResponse(t, returnedTrace, queriedV2Trace5B)

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

func TestTracesTempo(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envTracesTempoName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, tracesTempo, e)
	_, token, _ := startBaseServices(t, e, tracesTempo)

	tempoDistributorEndpoint, internalTempoQueryEndpoint, _ := startTempoServicesForTraces(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withGRPCListenEndpoint(":8317"),
		withOTLPGRPCTraceEndpoint(tempoDistributorEndpoint),
		withTempoEndpoint("http://"+internalTempoQueryEndpoint),

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
					"telemetry":    8888,
					"zpages":       55679,
				}).
			Init(e2e.StartOptions{
				Image: otelCollectorImage,
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
			bytes.NewBuffer([]byte(traceJSON5B)))
		testutil.Ok(t, err)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "{\"partialSuccess\":{}}")

		testutil.Equals(t, http.StatusOK, response.StatusCode)

		httpObservatoriumTempoEndpoint := fmt.Sprintf("https://%s/api/traces/v1/test-oidc/tempo", api.Endpoint("https"))
		// We skip TLS verification because Observatorium will present a cert for "e2e_traces_read_export-api",
		// but we contact it using "localhost".

		returnedTrace, _ := queryForTraceTempo(t, "valid Observatorium trace tempo query",
			httpObservatoriumTempoEndpoint, "5B8EFFF798038103D269B633813FC60C",
			true, fmt.Sprintf("bearer %s", token), http.StatusOK)
		assertResponse(t, returnedTrace, tempoTraceResponse5B)
	})
}
