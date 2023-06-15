//go:build integration

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	e2emon "github.com/efficientgo/e2e/monitoring"
	"github.com/efficientgo/e2e/monitoring/matchers"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

func TestMetricsReadAndWrite(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envMetricsName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, metrics, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, metrics)
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
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/api/v1/receive",
			withToken(token),
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Check that up queries / remote writes are correct (accounting for initial 5 sec query delay).
		minimumExpectedQueries := float64(1)
		minimumExpectedWrites := float64(21)

		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(minimumExpectedQueries),
			[]string{"up_queries_total"},
			e2emon.WaitMissingMetrics(),
		))

		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(minimumExpectedWrites),
			[]string{"up_remote_writes_total"},
		))

		testutil.Ok(t, up.Kill())

		// Check that API metrics are correct.
		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(minimumExpectedQueries+minimumExpectedWrites),
			[]string{"http_requests_total"},
		))

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
			testutil.Equals(t, 21, len(vs))
		}
	})
	t.Run("OIDC redirect protection", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-oidc-redirect-protection", metrics,
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/api/v1/receive",
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Wait until the first query is run.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.Equals(1),
			[]string{"up_queries_total"},
			e2emon.WaitMissingMetrics(),
		))

		// Check that up queries / remote writes are correct (accounting for initial 5 sec query delay).
		totalMetrics, err := up.SumMetrics([]string{"up_queries_total", "up_remote_writes_total"})
		testutil.Ok(t, err)

		totalQueries := float64(1)
		totalWrites := float64(21)
		testutil.Equals(t, totalQueries, totalMetrics[0])
		testutil.Equals(t, totalWrites, totalMetrics[1])

		errorMetrics, err := up.SumMetrics(
			[]string{"up_remote_writes_total"},
			e2emon.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "http_code", "400"),
			),
		)
		testutil.Ok(t, err)
		testutil.Equals(t, totalMetrics[1], errorMetrics[0])
		testutil.Ok(t, up.Stop())
	})
	// Query Thanos through Observatorium API to ensure we don't change API and the tenancy isolation is ensured.
	t.Run("metrics-tenant-isolation", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: getTLSClientConfig(t, e),
		}

		apiTest, err := promapi.NewClient(promapi.Config{
			Address:      "https://" + api.Endpoint("https") + "/api/metrics/v1/" + defaultTenantName,
			RoundTripper: &tokenRoundTripper{rt: tr, token: token},
		})
		testutil.Ok(t, err)
		apiAttacker, err := promapi.NewClient(promapi.Config{
			Address:      "https://" + api.Endpoint("https") + "/api/metrics/v1/test-attacker",
			RoundTripper: &tokenRoundTripper{rt: tr, token: token},
		})
		testutil.Ok(t, err)

		now := model.Now()
		t.Run("query", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).Query(context.Background(), "observatorium_write{}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)

			vs := strings.Split(v.String(), " => ")
			testutil.Equals(t, "observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\""+defaultTenantID+"\"}", vs[0])

			// Check timestamp.
			ts := strings.Split(vs[1], " @")
			testutil.Equals(t, fmt.Sprintf("[%v]", now), ts[1])

			// For attacker there should be no data.
			v, w, err = v1.NewAPI(apiAttacker).Query(context.Background(), "observatorium_write{}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings{"No StoreAPIs matched for this query"}, w)
			testutil.Equals(t, "", v.String())
		})
		t.Run("query_range", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).QueryRange(context.Background(), "observatorium_write{}", v1.Range{Start: now.Time().Add(-5 * time.Minute), End: now.Time(), Step: 1 * time.Minute})
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)

			vs := strings.Split(v.String(), " =>")
			testutil.Equals(t, "observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\""+defaultTenantID+"\"}", vs[0])

			// Check timestamp.
			ts := strings.Split(vs[1], " @")
			testutil.Equals(t, fmt.Sprintf("[%v]", now), ts[1])

			// For attacker there should be no data.
			v, w, err = v1.NewAPI(apiAttacker).QueryRange(context.Background(), "observatorium_write{}", v1.Range{Start: now.Time().Add(-5 * time.Minute), End: now.Time(), Step: 1 * time.Minute})
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings{"No StoreAPIs matched for this query"}, w)
			testutil.Equals(t, "", v.String())
		})
		t.Run("series", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).Series(context.Background(), []string{"observatorium_write{}"}, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, []model.LabelSet{{"__name__": "observatorium_write", "_id": "test", "receive_replica": "0", "tenant_id": "1610b0c3-c509-4592-a256-a1871353dbfa"}}, v)

			// For attacker there should be no data.
			v, w, err = v1.NewAPI(apiAttacker).Series(context.Background(), []string{"observatorium_write{}"}, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings{"No StoreAPIs matched for this query"}, w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})
		t.Run("label_names", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).LabelNames(context.Background(), nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, []string{"__name__", "_id", "receive_replica", "tenant_id"}, v)

			// For attacker there should be no data.
			v, w, err = v1.NewAPI(apiAttacker).LabelNames(context.Background(), nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})
		t.Run("labels_values", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).LabelValues(context.Background(), "__name__", nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, model.LabelValues{"observatorium_write"}, v)

			// For attacker there should be no data.
			v, w, err = v1.NewAPI(apiAttacker).LabelValues(context.Background(), "__name__", nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})
	})
}
