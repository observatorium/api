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

const recordingRuleYamlTpl = `
groups:
  - name: example
    interval: 30s
    rules:
      - record: job:http_inprogress_requests:sum
        expr: sum by (job) (http_inprogress_requests)
`

const alertingRuleYamlTpl = `
groups:
- name: example
  interval: 30s
  rules:
  - alert: HighRequestLatency
    expr: job:request_latency_seconds:mean5m{job="myjob"} > 0.5
    for: 10m
    labels:
      severity: page
    annotations:
      summary: High request latency
`
const recordAndAlertingRulesYamlTpl = `
groups:
- name: node_rules
  interval: 30s
  rules:
  - record: job:up:avg
    expr: avg without(instance)(up{job="node"})
  - alert: ManyInstancesDown
    expr: job:up:avg{job="node"} < 0.5
    for: 10m
    annotations:
      Summary: Many instances down
`

const invalidRulesYamlTpl = `
invalid:
- name: testing
 invalid_rules:
 - rule1: job:up:avg
   expr: avg without(instance)(up{job="node"})
 - rule2: ManyInstancesDown
   expr: job:up:avg{job="node"} < 0.5
`

const validYamlWithInvalidRulesYamlTpl = `
groups:
  - name: example
    interval: 30TB
    rules:
      - record: job:http_inprogress_requests:sum
        expr: sum by (job) (http_inprogress_requests)
      - alert: ManyInstancesDown
        expr: job:up:avg{job="node"} < 0.5
        for: 10GB
        annotations: {}
`

func TestRulesAPI(t *testing.T) {
	t.Parallel()

	e, err := e2e.NewDockerEnvironment(envRulesAPIName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, rules, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, rules)
	rulesEndpoint := startServicesForRules(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withRulesEndpoint("http://"+rulesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	rulesEndpointURL := "https://" + api.Endpoint("https") + "/api/metrics/v1/" + defaultTenantName + "/api/v1/rules/raw"
	tr := &http.Transport{
		TLSClientConfig: getTLSClientConfig(t, e),
	}

	client := &http.Client{
		Transport: &tokenRoundTripper{rt: tr, token: token},
	}

	t.Run("write-then-read-recording-rules", func(t *testing.T) {
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
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "sum by (job) (http_inprogress_requests)")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("write-then-read-alerting-rules", func(t *testing.T) {
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
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)
		assertResponse(t, bodyStr, "alert: HighRequestLatency")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("write-then-read-recording-and-alerting-rules", func(t *testing.T) {
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
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		bodyStr := string(body)
		assertResponse(t, bodyStr, "record: job:up:avg")
		assertResponse(t, bodyStr, "alert: ManyInstancesDown")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("write-invalid-rules", func(t *testing.T) {
		// Set an invalid rules file
		invalidRules := []byte(invalidRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(invalidRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusInternalServerError, res.StatusCode)
	})

	t.Run("write-valid-yaml-with-invalid-rules", func(t *testing.T) {
		// set valid YAML with invalid rules
		validYamlWithinvalidRules := []byte(validYamlWithInvalidRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			rulesEndpointURL,
			bytes.NewReader(validYamlWithinvalidRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusBadRequest, res.StatusCode)
	})

}
