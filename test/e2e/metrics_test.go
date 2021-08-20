package e2e

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// TODO: Standalone?
func TestMetricsReadAndWrite(t *testing.T) {
	t.Parallel()

	e, err := e2e.NewDockerEnvironment(envMetricsName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, metrics, e)
	token, rateLimiterAddr := startBaseServices(t, e, metrics)
	readEndpoint, writeEndpoint, readExtEndpoint := startServicesForMetrics(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("metrics-read-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-metrics-read-write", metrics,
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/receive",
			withToken(token),
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Wait until the first query is run.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2e.Equals(1),
			[]string{"up_queries_total"},
			e2e.WaitMissingMetrics(),
		))

		// Check that up queries / remote writes are correct (accounting for initial 5 sec query delay).
		upMetrics, err := up.SumMetrics([]string{"up_queries_total", "up_remote_writes_total"})
		testutil.Ok(t, err)
		testutil.Equals(t, float64(1), upMetrics[0])
		testutil.Equals(t, float64(11), upMetrics[1])

		testutil.Ok(t, up.Stop())

		// Check that API metrics are correct.
		apiMetrics, err := api.SumMetrics([]string{"http_requests_total"})
		testutil.Ok(t, err)
		testutil.Equals(t, float64(12), apiMetrics[0])

		// Query Thanos to ensure we have correct metrics and labels.
		a, err := promapi.NewClient(promapi.Config{Address: "http://" + readExtEndpoint})
		testutil.Ok(t, err)

		// Assert we have correct metrics and labels in Thanos.
		{
			now := model.Now()
			v, w, err := v1.NewAPI(a).Query(context.Background(), "observatorium_write{}", now.Time())

			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			vs := strings.Split(v.String(), " => ")
			testutil.Equals(t, "observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\""+defaultTenantID+"\"}", vs[0])

			// Check timestamp.
			ts := strings.Split(vs[1], " @")
			testutil.Equals(t, fmt.Sprintf("[%v]", now), ts[1])
		}

		// Assert we have recorded all sent values in the 1m range.
		{
			now := model.Now()
			v, w, err := v1.NewAPI(a).Query(context.Background(), "observatorium_write{}[1m]", now.Time())

			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			// Split on every value and ignore first line with metric name / labels.
			vs := strings.Split(v.String(), "\n")[1:]
			testutil.Equals(t, 11, len(vs))
		}
	})

	t.Run("metrics-tenant-isolation", func(t *testing.T) {
		r, err := http.NewRequest(
			http.MethodGet,
			"https://"+api.Endpoint("https")+"/api/metrics/v1/test-attacker/api/v1/query?query=observatorium_write",
			nil,
		)
		testutil.Ok(t, err)
		r.Header.Add("Authorization", "bearer "+token)

		c := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}

		res, err := c.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		testutil.Ok(t, err)

		assertResponse(t, string(body), "No StoreAPIs matched for this query")
	})
}
