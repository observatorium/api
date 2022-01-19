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

	rulesEndpointURL := "https://" + api.Endpoint("https") + "/api/metrics/v1/test-oidc/api/v1/rules/raw"
	tr := &http.Transport{
		TLSClientConfig: getTLSClientConfig(t, e),
	}

	client := &http.Client{
		Transport: &tokenRoundTripper{rt: tr, token: token},
	}

	t.Run("get-put-recording-rules", func(t *testing.T) {
		// Try to list rules
		r, err := http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusNotFound, res.StatusCode)

		// Set a file containing a recording rule
		recordingRule := []byte(recordingRuleYamlTpl)
		r, err = http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(recordingRule),
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

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
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "sum by (job) (http_inprogress_requests)")
	})

	t.Run("get-put-alerting-rules", func(t *testing.T) {
		// Set a file containing an alerting rule
		alertingRule := []byte(alertingRuleYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(alertingRule),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		// Check if the alerting rule is listed
		r, err = http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		defer res.Body.Close()

		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)
		assertResponse(t, bodyStr, "alert: HighRequestLatency")
	})

	t.Run("get-put-recording-alerting-rules", func(t *testing.T) {
		// Set a file containing both recording and alerting rules
		recordAndAlertingRules := []byte(recordAndAlertingRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(recordAndAlertingRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		// Check if both recording and alerting rules are listed
		r, err = http.NewRequest(
			http.MethodGet,
			rulesEndpointURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		defer res.Body.Close()

		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)
		assertResponse(t, bodyStr, "record: job:up:avg")
		assertResponse(t, bodyStr, "alert: ManyInstancesDown")
	})

	t.Run("put-invalid-rules", func(t *testing.T) {
		// Set an invalid rules file
		invalidRules := []byte(invalidRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(invalidRules),
		)
		testutil.Ok(t, err)
		res, err := client.Do(r)
		//TODO: an error/http status code is not being returned to the API
		//testutil.NotOk(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode) // should this be http.StatusBadRequest instead? (from: https://github.com/observatorium/rules-objstore/blob/main/pkg/server/server.go#L80)
	})
}