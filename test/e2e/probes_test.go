//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

func TestProbes_CreateAndGetProbe(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envProbesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, probes, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, probes)
	probesEndpoint := startServicesForProbes(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withProbesEndpoint("http://"+probesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("create-and-get-probe", func(t *testing.T) {
		// Test payload for creating a probe
		probePayload := map[string]interface{}{
			"static_url": "http://example.com/test",
			"status":     "pending",
			"labels": map[string]string{
				"env": "test",
			},
		}

		// Create probe
		payloadBytes, err := json.Marshal(probePayload)
		testutil.Ok(t, err)

		createURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes", api.InternalEndpoint("https"), defaultTenantName)
		req, err := http.NewRequest("POST", createURL, bytes.NewBuffer(payloadBytes))
		testutil.Ok(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}

		resp, err := client.Do(req)
		testutil.Ok(t, err)
		defer resp.Body.Close()

		testutil.Equals(t, http.StatusCreated, resp.StatusCode)

		// Parse response to get probe ID
		body, err := io.ReadAll(resp.Body)
		testutil.Ok(t, err)

		var createdProbe map[string]interface{}
		testutil.Ok(t, json.Unmarshal(body, &createdProbe))

		probeID, ok := createdProbe["id"].(string)
		testutil.Assert(t, ok, "probe ID should be a string")
		testutil.Assert(t, probeID != "", "probe ID should not be empty")

		// Get probe by ID
		getURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes/%s", api.InternalEndpoint("https"), defaultTenantName, probeID)
		getReq, err := http.NewRequest("GET", getURL, nil)
		testutil.Ok(t, err)
		getReq.Header.Set("Authorization", "Bearer "+token)

		getResp, err := client.Do(getReq)
		testutil.Ok(t, err)
		defer getResp.Body.Close()

		testutil.Equals(t, http.StatusOK, getResp.StatusCode)

		getBody, err := io.ReadAll(getResp.Body)
		testutil.Ok(t, err)

		var retrievedProbe map[string]interface{}
		testutil.Ok(t, json.Unmarshal(getBody, &retrievedProbe))

		// Verify the retrieved probe matches what we created
		testutil.Equals(t, probeID, retrievedProbe["id"].(string))
		testutil.Equals(t, "http://example.com/test", retrievedProbe["static_url"].(string))
		testutil.Equals(t, "pending", retrievedProbe["status"].(string))

		// Verify labels (including system labels)
		labels, ok := retrievedProbe["labels"].(map[string]interface{})
		testutil.Assert(t, ok, "labels should be a map")
		testutil.Equals(t, "test", labels["env"].(string))

		// System labels should be present
		testutil.Assert(t, labels["rhobs-synthetics/app"] != nil, "system app label should be present")
		testutil.Assert(t, labels["rhobs-synthetics/url-hash"] != nil, "system url-hash label should be present")
		testutil.Assert(t, labels["rhobs-synthetics/status"] != nil, "system status label should be present")
	})
}

func TestProbes_ListProbes(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envProbesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, probes, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, probes)
	probesEndpoint := startServicesForProbes(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withProbesEndpoint("http://"+probesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("list-probes", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}

		// Create a couple of test probes
		for i, env := range []string{"prod", "test"} {
			probePayload := map[string]interface{}{
				"static_url": fmt.Sprintf("http://example.com/probe-%d", i),
				"status":     "pending",
				"labels": map[string]string{
					"env": env,
				},
			}

			payloadBytes, err := json.Marshal(probePayload)
			testutil.Ok(t, err)

			createURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes", api.InternalEndpoint("https"), defaultTenantName)
			req, err := http.NewRequest("POST", createURL, bytes.NewBuffer(payloadBytes))
			testutil.Ok(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			testutil.Ok(t, err)
			resp.Body.Close()
			testutil.Equals(t, http.StatusCreated, resp.StatusCode)
		}

		// List all probes
		listURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes", api.InternalEndpoint("https"), defaultTenantName)
		listReq, err := http.NewRequest("GET", listURL, nil)
		testutil.Ok(t, err)
		listReq.Header.Set("Authorization", "Bearer "+token)

		listResp, err := client.Do(listReq)
		testutil.Ok(t, err)
		defer listResp.Body.Close()

		testutil.Equals(t, http.StatusOK, listResp.StatusCode)

		listBody, err := io.ReadAll(listResp.Body)
		testutil.Ok(t, err)

		var probes []map[string]interface{}
		testutil.Ok(t, json.Unmarshal(listBody, &probes))

		// Should have at least 2 probes
		testutil.Assert(t, len(probes) >= 2, "should have at least 2 probes")

		// Test label selector filtering
		filterURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes?label_selector=env=prod", api.InternalEndpoint("https"), defaultTenantName)
		filterReq, err := http.NewRequest("GET", filterURL, nil)
		testutil.Ok(t, err)
		filterReq.Header.Set("Authorization", "Bearer "+token)

		filterResp, err := client.Do(filterReq)
		testutil.Ok(t, err)
		defer filterResp.Body.Close()

		testutil.Equals(t, http.StatusOK, filterResp.StatusCode)

		filterBody, err := io.ReadAll(filterResp.Body)
		testutil.Ok(t, err)

		var filteredProbes []map[string]interface{}
		testutil.Ok(t, json.Unmarshal(filterBody, &filteredProbes))

		// Should have exactly 1 probe with env=prod
		testutil.Equals(t, 1, len(filteredProbes))

		labels, ok := filteredProbes[0]["labels"].(map[string]interface{})
		testutil.Assert(t, ok, "labels should be a map")
		testutil.Equals(t, "prod", labels["env"].(string))
	})
}

func TestProbes_CreateProbeConflict(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envProbesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, probes, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, probes)
	probesEndpoint := startServicesForProbes(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withProbesEndpoint("http://"+probesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("create-probe-conflict", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}

		probePayload := map[string]interface{}{
			"static_url": "http://example.com/duplicate",
			"status":     "pending",
			"labels": map[string]string{
				"env": "test",
			},
		}

		payloadBytes, err := json.Marshal(probePayload)
		testutil.Ok(t, err)

		createURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes", api.InternalEndpoint("https"), defaultTenantName)

		// Create first probe
		req1, err := http.NewRequest("POST", createURL, bytes.NewBuffer(payloadBytes))
		testutil.Ok(t, err)
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/json")

		resp1, err := client.Do(req1)
		testutil.Ok(t, err)
		resp1.Body.Close()
		testutil.Equals(t, http.StatusCreated, resp1.StatusCode)

		// Attempt to create second probe with same URL
		req2, err := http.NewRequest("POST", createURL, bytes.NewBuffer(payloadBytes))
		testutil.Ok(t, err)
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := client.Do(req2)
		testutil.Ok(t, err)
		defer resp2.Body.Close()

		// Should get conflict response
		testutil.Equals(t, http.StatusConflict, resp2.StatusCode)
	})
}

func TestProbes_UnauthorizedAccess(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envProbesName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, probes, e)
	_, _, rateLimiterAddr := startBaseServices(t, e, probes)
	probesEndpoint := startServicesForProbes(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withProbesEndpoint("http://"+probesEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("unauthorized-access", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}

		// Test without authorization header
		listURL := fmt.Sprintf("https://%s/api/probes/v1/%s/probes", api.InternalEndpoint("https"), defaultTenantName)
		req, err := http.NewRequest("GET", listURL, nil)
		testutil.Ok(t, err)
		// Deliberately not setting Authorization header

		resp, err := client.Do(req)
		testutil.Ok(t, err)
		defer resp.Body.Close()

		// Should get unauthorized response
		testutil.Equals(t, http.StatusUnauthorized, resp.StatusCode)

		// Test with invalid token
		reqInvalid, err := http.NewRequest("GET", listURL, nil)
		testutil.Ok(t, err)
		reqInvalid.Header.Set("Authorization", "Bearer invalid-token")

		respInvalid, err := client.Do(reqInvalid)
		testutil.Ok(t, err)
		defer respInvalid.Body.Close()

		// Should get unauthorized or forbidden response
		testutil.Assert(t, respInvalid.StatusCode == http.StatusUnauthorized || respInvalid.StatusCode == http.StatusForbidden,
			fmt.Sprintf("expected 401 or 403, got %d", respInvalid.StatusCode))
	})
}
