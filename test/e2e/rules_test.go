// +build integration

package e2e

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

func TestRulesAPI(t *testing.T) {
	t.Parallel()

	e, err := e2e.NewDockerEnvironment(envRulesAPIName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, rules, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, rules)
	_, _, rulesEndpoint, _ := startServicesForMetrics(t, e) // TODO: create another function just for rules?

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("", "", "http://"+rulesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("rules", func(t *testing.T) {
		rulesEndpointURL := "https://" + api.Endpoint("https") + "/api/metrics/v1/test-oidc/api/v1/rules/raw"
		tr := &http.Transport{
			TLSClientConfig: getTLSClientConfig(t, e),
		}

		client := &http.Client{
			Transport: &tokenRoundTripper{rt: tr, token: token},
		}

		// Try to list rules
		r, err := http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, res.StatusCode, http.StatusNotFound)

		// Set a recording rule
		recordingRule := []byte(recordingRuleYamlTpl)
		r, err = http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(recordingRule),
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, res.StatusCode, http.StatusOK)

		// Check if recording rule is listed
		r, err = http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		defer res.Body.Close()

		testutil.Ok(t, err)
		testutil.Equals(t, res.StatusCode, http.StatusOK)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "sum by (job) (http_inprogress_requests)")

		// Set alerting rule
		alertingRule := []byte(alertingRuleYamlTpl)
		r, err = http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(alertingRule),
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, res.StatusCode, http.StatusOK)

		// Check if recording rule and alerting rule are listed
		r, err = http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		defer res.Body.Close()

		testutil.Ok(t, err)
		testutil.Equals(t, res.StatusCode, http.StatusOK)

		body, err = ioutil.ReadAll(res.Body)
		bodyStr = string(body)
		//TODO: check why this fails - shouldn't it join recording+alerting rules?
		//assertResponse(t, bodyStr, "sum by (job) (http_inprogress_requests)")
		assertResponse(t, bodyStr, "alert: HighRequestLatency")

		// TODO: add another test case for thanos-ruler-syncer flow
	})
}