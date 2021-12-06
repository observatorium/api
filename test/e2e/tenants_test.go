// +build integration

package e2e

import (
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/e2e/matchers"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

func TestTenantsRetryAuthenticationProviderRegistration(t *testing.T) {
	t.Parallel()

	e, err := e2e.NewDockerEnvironment(envTenantsName)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, tenants, e)
	dex, _, _ := startBaseServices(t, e, tenants)
	readEndpoint, writeEndpoint, rulesEndpoint, _ := startServicesForMetrics(t, e)

	// Start API with stopped Dex and observe retries.
	dex.Stop()

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint, "http://"+rulesEndpoint),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("tenants-authenticator-provider-retry", func(t *testing.T) {
		// Check that retries metric increases eventually.
		// This is with the new authenticators setup.
		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2e.Greater(0),
			[]string{"observatorium_api_tenants_failed_registrations"},
			e2e.WaitMissingMetrics(),
			e2e.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "tenant", "test-oidc"),
				matchers.MustNewMatcher(matchers.MatchEqual, "provider", "oidc"),
			),
		))

		// Test a tenant with legacy configuration setup.
		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2e.Greater(0),
			[]string{"observatorium_api_tenants_failed_registrations"},
			e2e.WaitMissingMetrics(),
			e2e.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "tenant", "test-attacker"),
				matchers.MustNewMatcher(matchers.MatchEqual, "provider", "oidc"),
			),
		))

		// Restart Dex.
		testutil.Ok(t, e2e.StartAndWaitReady(dex))
		token, err := obtainToken(dex.Endpoint("https"), getTLSClientConfig(t, e))
		testutil.Ok(t, err)

		up, err := newUpRun(
			e, "up-tenants", metrics,
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/receive",
			withToken(token),
			withRunParameters(&runParams{initialDelay: "100ms", period: "300ms", threshold: "1", latency: "5s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		// Check that we succesfully hit API after re-registration.
		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2e.Greater(0),
			[]string{"http_requests_total"},
			e2e.WaitMissingMetrics(),
			e2e.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "code", "200"),
			),
		))

	})

}
