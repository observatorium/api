//go:build integration

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/prometheus/alertmanager/api/v2/models"

	httptransport "github.com/go-openapi/runtime/client"
	client2 "github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/client/silence"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

func TestAlertmanagerApiProxy(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envAlertmanagerName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, alerts, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, alerts)
	alertmanagerEndpoint := newAlertmanagerService(e)
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)
	testutil.Ok(t, e2e.StartAndWaitReady(alertmanagerEndpoint))

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withAlertmanagerEndpoint("http://"+alertmanagerEndpoint.InternalEndpoint("http")),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	authClient := &http.Client{
		Transport: &tokenRoundTripper{
			rt: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			}, token: token},
	}

	t.Run("alerts-check-then-write-then-read", func(t *testing.T) {
		// create a alertmanager that goes through the gateway proxy and requires auth token
		runtime := httptransport.New(api.Endpoint("https"), "/api/metrics/v1/test-oidc/am"+client2.DefaultBasePath, []string{"https"})
		tenantAlertmanagerClient := alert.New(runtime, strfmt.Default)

		// create an alertmanager client that goes directly to the alertmanager
		runtimeYolo := httptransport.New(alertmanagerEndpoint.Endpoint("http"), client2.DefaultBasePath, []string{"http"})
		adminAlertmanagerClient := alert.New(runtimeYolo, strfmt.Default)

		// Check that there are no alerts
		alertsResult, err := adminAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 0, len(alertsResult.Payload))

		// Create two alerts with the alertmanager client
		ok, err := adminAlertmanagerClient.PostAlerts(
			&alert.PostAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
				Alerts: []*models.PostableAlert{
					{
						Annotations: models.LabelSet{
							"test": "true",
						},
						StartsAt: strfmt.DateTime(time.Now()),
						EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-a",
								"severity":  "critical",
								"tenant_id": "1610b0c3-c509-4592-a256-a1871353dbfa",
							},
							GeneratorURL: "http://localhost",
						},
					},
					{
						Annotations: models.LabelSet{
							"test": "true",
						},
						StartsAt: strfmt.DateTime(time.Now()),
						EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-a-warn",
								"severity":  "warning",
								"tenant_id": "1610b0c3-c509-4592-a256-a1871353dbfa",
							},
							GeneratorURL: "http://localhost",
						},
					},
					{
						Annotations: models.LabelSet{
							"test": "true",
						},
						StartsAt: strfmt.DateTime(time.Now()),
						EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-b",
								"severity":  "critical",
								"tenant_id": "tenant-b",
							},
							GeneratorURL: "http://localhost",
						},
					},
				},
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)
		// read the results with the admin client
		alertsResult, err = adminAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 3, "expected 3 alerts, got %d", len(alertsResult.Payload))

		// read the results with the tenants client
		alertsResult, err = tenantAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		// assert that the tenant only gets back the alert with their own tenant_id	label
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 2, "expected 2 alerts, got %d", len(alertsResult.Payload))
		testutil.Equals(t, []string{"test-alert-tenant-a", "test-alert-tenant-a-warn"},
			[]string{alertsResult.Payload[1].Labels["alertname"], alertsResult.Payload[0].Labels["alertname"]},
		)
	})

	t.Run("silence-check-then-write-then-read", func(t *testing.T) {
		// create a alertmanager that goes through the gateway proxy and requires auth token
		runtime := httptransport.New(api.Endpoint("https"), "/api/metrics/v1/test-oidc/am"+client2.DefaultBasePath, []string{"https"})
		tenantSilenceClient := silence.New(runtime, strfmt.Default)

		// create an alertmanager client that goes directly to the alertmanager
		runtimeYolo := httptransport.New(alertmanagerEndpoint.Endpoint("http"), client2.DefaultBasePath, []string{"http"})
		adminSilenceClient := silence.New(runtimeYolo, strfmt.Default)
		adminAlertClient := alert.New(runtimeYolo, strfmt.Default)

		// Check that there are no silences
		silenceResult, err := adminSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 0, len(silenceResult.Payload))

		// Create a silence with the tenant client
		// this should match two alerts but only silence one due to the tenant_id label
		ok, err := tenantSilenceClient.PostSilences(
			&silence.PostSilencesParams{
				Silence: &models.PostableSilence{
					Silence: models.Silence{
						CreatedBy: toStrPtr(t, "test"),
						Comment:   toStrPtr(t, "test"),
						StartsAt:  toDateTimePtr(t, time.Now()),
						EndsAt:    toDateTimePtr(t, time.Now().Add(time.Hour)),
						Matchers: []*models.Matcher{
							{
								IsEqual: toBoolPtr(t, true),
								IsRegex: toBoolPtr(t, false),
								Name:    toStrPtr(t, "severity"),
								Value:   toStrPtr(t, "critical"),
							},
						},
					},
				},
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		// read the results with the admin client
		alertsResult, err := adminAlertClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 3, "expected 3 alerts, got %d", len(alertsResult.Payload))

		var silenced int
		for _, alert := range alertsResult.Payload {
			if len(alert.Status.SilencedBy) > 0 {
				silenced++
			}
		}
		testutil.Assert(t, silenced == 1, "expected 1 silenced alert, got %d", silenced)

		// Create a silence with the admin client
		// this should match two alerts and silence them
		ok, err = adminSilenceClient.PostSilences(
			&silence.PostSilencesParams{
				Silence: &models.PostableSilence{
					Silence: models.Silence{
						CreatedBy: toStrPtr(t, "admin"),
						Comment:   toStrPtr(t, "admin"),
						StartsAt:  toDateTimePtr(t, time.Now()),
						EndsAt:    toDateTimePtr(t, time.Now().Add(time.Hour)),
						Matchers: []*models.Matcher{
							{
								IsEqual: toBoolPtr(t, true),
								IsRegex: toBoolPtr(t, false),
								Name:    toStrPtr(t, "severity"),
								Value:   toStrPtr(t, "critical"),
							},
						},
					},
				},
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		// read the results with the admin client
		adminSilenceResult, err := adminSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 2, len(adminSilenceResult.Payload))

		// read the results with the tenant client
		tenantSilenceResult, err := tenantSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 1, len(tenantSilenceResult.Payload))

	})
}

func testContextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	return ctx
}

func toStrPtr(t *testing.T, s string) *string {
	t.Helper()
	return &s
}

func toDateTimePtr(t *testing.T, time time.Time) *strfmt.DateTime {
	t.Helper()
	dt := strfmt.DateTime(time)
	return &dt
}

func toBoolPtr(t *testing.T, b bool) *bool {
	t.Helper()
	return &b
}
