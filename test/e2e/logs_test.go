package e2e

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/gorilla/websocket"
)

func TestLogsReadWriteAndTail(t *testing.T) {
	e, err := e2e.NewDockerEnvironment("e2e_observatorium_api")
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	certsContainerDir, err := copyTestDir(e.SharedDir(), "../../tmp/certs", "certs")
	testutil.Ok(t, err)

	configsContainerDir, err := copyTestDir(e.SharedDir(), "../config", "config")
	testutil.Ok(t, err)

	_, _, _, lokiEndpoint, lokiExtEndpoint, rateLimiter, token := startAndWaitOnBaseServices(t, e, configsContainerDir, certsContainerDir)

	api, err := newObservatoriumAPIService(
		e, "observatorium-api", lokiEndpoint, lokiEndpoint, lokiEndpoint, "", "",
		filepath.Join(configsContainerDir, "rbac.yaml"), filepath.Join(configsContainerDir, "tenants.yaml"),
		certsContainerDir, rateLimiter,
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("logs-read-write", func(t *testing.T) {
		up, err := newUpService(
			e, "observatorium-up", "logs",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-mtls/loki/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-mtls/loki/api/v1/push",
			certsContainerDir,
			token,
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Wait until 10 queries are run.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2e.Equals(10),
			[]string{"up_queries_total"},
			e2e.WaitMissingMetrics(),
		))

		// Check that up metrics are correct.
		upMetrics, err := up.SumMetrics([]string{"up_queries_total", "up_remote_writes_total"})
		testutil.Ok(t, err)
		testutil.Equals(t, upMetrics[0], float64(10))
		testutil.Equals(t, upMetrics[1], float64(20))

		testutil.Ok(t, up.Stop())

		// Check that API metrics are correct.
		apiMetrics, err := api.SumMetrics([]string{"http_requests_total"})
		testutil.Ok(t, err)
		testutil.Equals(t, apiMetrics[0], float64(30))

		// Simple test to check if we can query Loki for logs.
		r, err := http.NewRequest(
			http.MethodGet,
			"http://"+lokiExtEndpoint+"/loki/api/v1/query",
			nil,
		)
		testutil.Ok(t, err)

		v := url.Values{}
		v.Add("query", "{_id=\"test\"}")
		r.URL.RawQuery = v.Encode()
		// TODO: Replace with constants - tenant names, IDs, etc.?
		r.Header.Add("X-Scope-OrgID", "845cdfd9-f936-443c-979c-2ee7dc91f646")

		res, err := http.DefaultClient.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		testutil.Ok(t, err)

		respRegexp := regexp.MustCompile(
			`\"result\":\[{\"stream\":{\"__name__\":\"observatorium_write\",\"_id\":\"test\"},\"values\":\[\[\"[0-9]{19}\",\"log line 1\"\]\]}\]`,
		)
		testutil.Assert(
			t,
			respRegexp.Match(body),
			fmt.Sprintf("failed to assert that the response '%s' matches '%s'", string(body), respRegexp),
		)

	})

	t.Run("logs-tail", func(t *testing.T) {
		up, err := newUpService(
			e, "observatorium-up-logs-tail", "logs",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-oidc/loki/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/logs/v1/test-oidc/loki/api/v1/push",
			certsContainerDir,
			token,
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Wait until 10 queries are run.
		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2e.Equals(1),
			[]string{"up_queries_total"},
			e2e.WaitMissingMetrics(),
		))

		testutil.Ok(t, up.Stop())

		d := websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		// TODO: Generate certs?

		conn, _, err := d.Dial(
			"wss://"+api.Endpoint("https")+"/api/logs/v1/test-oidc/loki/api/v1/tail?query=%7B_id%3D%22test%22%7D",
			http.Header{
				"Authorization": []string{"Bearer " + token},
				"X-Scope-OrgID": []string{"1610b0c3-c509-4592-a256-a1871353dbfa"},
			},
		)
		testutil.Ok(t, err)
		defer conn.Close()

		_, message, err := conn.ReadMessage()
		testutil.Ok(t, err)

		respRegexp := regexp.MustCompile(
			`\"streams\":\[{\"stream\":{\"__name__\":\"observatorium_write\",\"_id\":\"test\"},\"values\":\[\[\"[0-9]{19}\",\"log line 1\"\]\]}\]`,
		)
		testutil.Assert(
			t,
			respRegexp.Match(message),
			fmt.Sprintf("failed to assert that the response '%s' matches '%s'", string(message), respRegexp),
		)
	})
}
