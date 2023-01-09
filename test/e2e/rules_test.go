//go:build integration

package e2e

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

const logsAlertingRuleYamlTpl = `
name: test-firing-alert
interval: 30s
rules:
  - alert: TestFiringAlert
    annotations:
      description: Test firing alert
    expr: |
      1 > 0
    for: 1s
    labels:
      severity: warn
      source: logs
`

const logsRecordingRuleYamlTpl = `
interval: 30s
name: test-firing-alert
rules:
  - record: test:metric
    expr: |
      sum(
        rate({container="nginx"}[1m])
      )
    labels:
      severity: warn
      source: logs
`

const metricsRecordingRuleYamlTpl = `
groups:
 - name: example
   interval: 30s
   rules:
     - record: id_network_type
       expr: 0 * topk by (ebs_account) (1, max by (ebs_account,account_type,internal,email_domain) (label_replace(label_replace(label_replace(subscription_labels{email_domain="domain1.com"}*0+5, "class", "Internal", "class", ".*") or label_replace(subscription_labels{class!="Customer",email_domain=~"(.*\\.|^)domain2.com"}*0+4, "class", "Internal", "class", ".*") or (subscription_labels{class="Customer"}*0+3) or (subscription_labels{class="Partner"}*0+2) or (subscription_labels{class="Evaluation"}*0+1) or label_replace(subscription_labels{class!~"Evaluation|Customer|Partner"}*0+0, "class", "", "class", ".*"), "account_type", "$1", "class", "(.+)"), "internal", "true", "email_domain", "domain1.com|(.*\\.|^)domain2.com") ))
`

const metricsAlertingRuleYamlTpl = `
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

const metricsRecordAndAlertingRulesYamlTpl = `
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

const metricsInvalidRulesYamlTpl = `
invalid:
- name: testing
 invalid_rules:
 - rule1: job:up:avg
   expr: avg without(instance)(up{job="node"})
 - rule2: ManyInstancesDown
   expr: job:up:avg{job="node"} < 0.5
`

const metricsValidYamlWithInvalidRulesYamlTpl = `
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

	e, err := e2e.New(e2e.WithName(envRulesAPIName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, rules, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, rules)
	metricsRulesEndpoint := startServicesForRules(t, e)
	logsRulesEndpoint, _ := startServicesForLogs(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withRulesEndpoint("http://"+metricsRulesEndpoint),
		withLogsEndpoints("http://"+logsRulesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	logsRulesURL := "https://" + api.Endpoint("https") + "/api/logs/v1/" + defaultTenantName + "/loki/api/v1/rules"
	metricsRulesURL := "https://" + api.Endpoint("https") + "/api/metrics/v1/" + defaultTenantName + "/api/v1/rules/raw"
	tr := &http.Transport{
		TLSClientConfig: getTLSClientConfig(t, e),
	}

	client := &http.Client{
		Transport: &tokenRoundTripper{rt: tr, token: token},
	}

	t.Run("metrics-write-then-read-recording-rules", func(t *testing.T) {
		// Try to list rules
		r, err := http.NewRequest(
			http.MethodGet,
			metricsRulesURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusNotFound, res.StatusCode)

		// Set a file containing a recording rule
		recordingRule := []byte(metricsRecordingRuleYamlTpl)
		r, err = http.NewRequest(
			http.MethodPut,
			metricsRulesURL,
			bytes.NewReader(recordingRule),
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		// Check if recording rule is listed
		r, err = http.NewRequest(
			http.MethodGet,
			metricsRulesURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "subscription_labels{email_domain=\"domain1.com\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "subscription_labels{class!=\"Customer\",email_domain=~\"(.*\\\\.|^)domain2.com\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "subscription_labels{class=\"Customer\",tenant_id=\""+defaultTenantID+"\"")
		assertResponse(t, bodyStr, "subscription_labels{class=\"Partner\",tenant_id=\""+defaultTenantID+"\"")
		assertResponse(t, bodyStr, "subscription_labels{class=\"Evaluation\",tenant_id=\""+defaultTenantID+"\"")
		assertResponse(t, bodyStr, "subscription_labels{class!~\"Evaluation|Customer|Partner\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("metrics-write-then-read-alerting-rules", func(t *testing.T) {
		// Set a file containing an alerting rule
		alertingRule := []byte(metricsAlertingRuleYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			metricsRulesURL,
			bytes.NewReader(alertingRule),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		// Check if the alerting rule is listed
		r, err = http.NewRequest(
			http.MethodGet,
			metricsRulesURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "alert: HighRequestLatency")
		assertResponse(t, bodyStr, "job:request_latency_seconds:mean5m{job=\"myjob\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("metrics-write-then-read-recording-and-alerting-rules", func(t *testing.T) {
		// Set a file containing both recording and alerting rules
		recordAndAlertingRules := []byte(metricsRecordAndAlertingRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			metricsRulesURL,
			bytes.NewReader(recordAndAlertingRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusOK, res.StatusCode)

		// Check if both recording and alerting rules are listed
		r, err = http.NewRequest(
			http.MethodGet,
			metricsRulesURL,
			nil,
		)
		testutil.Ok(t, err)

		res, err = client.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "record: job:up:avg")
		assertResponse(t, bodyStr, "alert: ManyInstancesDown")
		assertResponse(t, bodyStr, "up{job=\"node\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "job:up:avg{job=\"node\",tenant_id=\""+defaultTenantID+"\"}")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("metrics-write-invalid-rules", func(t *testing.T) {
		// Set an invalid rules file
		invalidRules := []byte(metricsInvalidRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			metricsRulesURL,
			bytes.NewReader(invalidRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusInternalServerError, res.StatusCode)
	})

	t.Run("metrics-write-valid-yaml-with-invalid-rules", func(t *testing.T) {
		// set valid YAML with invalid rules
		validYamlWithinvalidRules := []byte(metricsValidYamlWithInvalidRulesYamlTpl)
		r, err := http.NewRequest(
			http.MethodPut,
			metricsRulesURL,
			bytes.NewReader(validYamlWithinvalidRules),
		)
		testutil.Ok(t, err)

		res, err := client.Do(r)
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("logs-write-then-read-alerting-rules", func(t *testing.T) {
		// Set a file containing an alerting rule
		alertingRule := []byte(logsAlertingRuleYamlTpl)

		res, err := client.Post(logsRulesURL+"/"+defaultTenantName, "application/yaml", bytes.NewReader(alertingRule))
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusAccepted, res.StatusCode)

		res, err = client.Get(logsRulesURL)
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "alert: TestFiringAlert")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("logs-write-then-read-recording-rules", func(t *testing.T) {
		// Set a file containing a recording rule
		recordingRule := []byte(logsRecordingRuleYamlTpl)

		res, err := client.Post(logsRulesURL+"/"+defaultTenantName, "application/yaml", bytes.NewReader(recordingRule))
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusAccepted, res.StatusCode)

		res, err = client.Get(logsRulesURL)
		testutil.Ok(t, err)
		defer res.Body.Close()

		testutil.Equals(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		bodyStr := string(body)

		assertResponse(t, bodyStr, "record: test:metric")
		assertResponse(t, bodyStr, "tenant_id: "+defaultTenantID)
	})

	t.Run("logs-write-tenant-not-matching-namespace", func(t *testing.T) {
		// Set a file containing an alerting rule
		alertingRule := []byte(logsAlertingRuleYamlTpl)

		res, err := client.Post(logsRulesURL+"/nonsense", "application/yaml", bytes.NewReader(alertingRule))
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("logs-read-tenant-not-matching-namespace", func(t *testing.T) {
		res, err := client.Get(logsRulesURL + "/nonsense")
		testutil.Ok(t, err)
		testutil.Equals(t, http.StatusBadRequest, res.StatusCode)
	})
}
