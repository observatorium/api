//go:build integration

package e2e

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	e2emon "github.com/efficientgo/e2e/monitoring"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	"github.com/gorilla/websocket"
)

func TestLogs(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envLogsName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, logs, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, logs)
	logsEndpoint, logsExtEndpoint := startServicesForLogs(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withLogsEndpoints("http://"+logsEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("read-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-logs-read-write", logs,
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-mtls/loki/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-mtls/loki/api/v1/push",
			withToken(token),
			withRunParameters(&runParams{initialDelay: "100ms", period: "1s", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Check that up metrics are correct.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(5),
			[]string{"up_queries_total"},
			e2emon.WaitMissingMetrics(),
		))

		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(12),
			[]string{"up_remote_writes_total"},
			e2emon.WaitMissingMetrics(),
		))

		testutil.Ok(t, up.Kill())

		// Check that API metrics are correct.
		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(24),
			[]string{"http_requests_total"},
			e2emon.WaitMissingMetrics(),
		))

		// Simple test to check if we can query Loki for logs.
		r, err := http.NewRequest(
			http.MethodGet,
			"http://"+logsExtEndpoint+"/loki/api/v1/query",
			nil,
		)
		testutil.Ok(t, err)

		v := url.Values{}
		v.Add("query", "{_id=\"test\"}")
		r.URL.RawQuery = v.Encode()
		r.Header.Add("X-Scope-OrgID", mtlsTenantID)

		res, err := http.DefaultClient.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		testutil.Ok(t, err)

		bodyStr := string(body)
		assertResponse(t, bodyStr, "\"__name__\":\"observatorium_write\"")
		assertResponse(t, bodyStr, "\"_id\":\"test\"")
		assertResponse(t, bodyStr, "log line 1")

	})

	t.Run("tail-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-logs-tail", logs,
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/"+defaultTenantName+"/loki/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/"+defaultTenantName+"/loki/api/v1/push",
			withToken(token),
			withRunParameters(&runParams{initialDelay: "0s", period: "250ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Wait until the first query is run.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(1),
			[]string{"up_queries_total"},
			e2emon.WaitMissingMetrics(),
		))

		testutil.Ok(t, up.Stop())

		d := websocket.Dialer{TLSClientConfig: getTLSClientConfig(t, e)}
		conn, _, err := d.Dial(
			"wss://"+api.Endpoint("https")+"/api/logs/v1/"+defaultTenantName+"/loki/api/v1/tail?query=%7B_id%3D%22test%22%7D",
			http.Header{
				"Authorization": []string{"Bearer " + token},
				"X-Scope-OrgID": []string{defaultTenantID},
			},
		)
		testutil.Ok(t, err)
		defer conn.Close()

		_, message, err := conn.ReadMessage()
		testutil.Ok(t, err)

		messageStr := string(message)
		assertResponse(t, messageStr, "\"__name__\":\"observatorium_write\"")
		assertResponse(t, messageStr, "\"_id\":\"test\"")
		assertResponse(t, messageStr, "log line 1")
	})
}
