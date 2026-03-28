//go:build integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

const otlpMetricsJSON = `
{
  "resourceMetrics": [
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
      "scopeMetrics": [
        {
          "scope": {
            "name": "my.library",
            "version": "1.0.0"
          },
          "metrics": [
            {
              "name": "otlp_test_gauge",
              "unit": "1",
              "gauge": {
                "dataPoints": [
                  {
                    "asDouble": 42.0,
                    "timeUnixNano": "%d",
                    "attributes": [
                      {
                        "key": "testlabel",
                        "value": {
                          "stringValue": "testvalue"
                        }
                      }
                    ]
                  }
                ]
              }
            }
          ]
        }
      ]
    }
  ]
}`

func TestMetricsOTLPWrite(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envMetricsOTLPName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, metricsOTLP, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, metricsOTLP)
	readEndpoint, writeEndpoint, readExtEndpoint, otlpHTTPEndpoint := startServicesForMetricsOTLP(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withOTLPHTTPMetricsEndpoint("http://"+otlpHTTPEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("write-otlp-http-then-query", func(t *testing.T) {
		now := time.Now()
		metricsPayload := fmt.Sprintf(otlpMetricsJSON, now.UnixNano())

		tlsClientConfig := getTLSClientConfig(t, e)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsClientConfig}}

		otlpURL := fmt.Sprintf(
			"https://%s/api/metrics/v1/%s/otlp/v1/metrics",
			api.Endpoint("https"),
			defaultTenantName,
		)

		request, err := http.NewRequest("POST", otlpURL, bytes.NewBuffer([]byte(metricsPayload)))
		testutil.Ok(t, err)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", fmt.Sprintf("bearer %s", token))

		response, err := client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		testutil.Ok(t, err)

		t.Logf("OTLP write response status: %d, body: %s", response.StatusCode, string(body))
		testutil.Equals(t, http.StatusOK, response.StatusCode)

		// Query Thanos to verify the metric arrived.
		tr := &http.Transport{TLSClientConfig: getTLSClientConfig(t, e)}
		apiClient, err := promapi.NewClient(promapi.Config{
			Address:      "https://" + api.Endpoint("https") + "/api/metrics/v1/" + defaultTenantName,
			RoundTripper: &tokenRoundTripper{rt: tr, token: token},
		})
		testutil.Ok(t, err)

		queryAPI := v1.NewAPI(apiClient)

		// Retry query to allow time for the metric to propagate through the collector and Thanos.
		var queryResult model.Value
		testutil.Ok(t, retryUntil(30*time.Second, 2*time.Second, func() error {
			var err error
			queryResult, _, err = queryAPI.Query(context.Background(), `otlp_test_gauge{testlabel="testvalue"}`, time.Now())
			if err != nil {
				return err
			}
			if queryResult.String() == "" {
				return fmt.Errorf("no results yet")
			}
			return nil
		}))

		resultStr := queryResult.String()
		t.Logf("Query result: %s", resultStr)
		assertResponse(t, resultStr, "otlp_test_gauge")
		assertResponse(t, resultStr, `testlabel="testvalue"`)
	})

	t.Run("write-otlp-http-unauthenticated", func(t *testing.T) {
		now := time.Now()
		metricsPayload := fmt.Sprintf(otlpMetricsJSON, now.UnixNano())

		tlsClientConfig := getTLSClientConfig(t, e)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsClientConfig}}

		otlpURL := fmt.Sprintf(
			"https://%s/api/metrics/v1/%s/otlp/v1/metrics",
			api.Endpoint("https"),
			defaultTenantName,
		)

		request, err := http.NewRequest("POST", otlpURL, bytes.NewBuffer([]byte(metricsPayload)))
		testutil.Ok(t, err)
		request.Header.Set("Content-Type", "application/json")
		// No Authorization header - should fail.

		response, err := client.Do(request)
		testutil.Ok(t, err)
		defer response.Body.Close()

		// Without auth, we expect a redirect or error (not 200).
		testutil.Assert(t, response.StatusCode != http.StatusOK,
			fmt.Sprintf("expected non-200 status for unauthenticated request, got %d", response.StatusCode))
	})

	_ = readExtEndpoint
}

func retryUntil(timeout, interval time.Duration, f func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = f()
		if lastErr == nil {
			return nil
		}
		time.Sleep(interval)
	}
	return fmt.Errorf("timed out after %s: %w", timeout, lastErr)
}
