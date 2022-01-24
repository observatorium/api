// +build interactive

package e2e

import (
	"fmt"
	"testing"

	"github.com/efficientgo/e2e"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

func TestInteractiveSetup(t *testing.T) {
	fmt.Printf("Starting services...\n")

	e, err := e2e.NewDockerEnvironment(envInteractive)
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, interactive, e)
	_, token, rateLimiterAddr := startBaseServices(t, e, interactive)
	readEndpoint, writeEndpoint, readExtEndpoint := startServicesForMetrics(t, e)
	logsEndpoint, logsExtEndpoint := startServicesForLogs(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withLogsEndpoints("http://"+logsEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	up, err := newUpRun(
		e, "up-metrics-read-write", metrics,
		"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/api/v1/query",
		"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/"+defaultTenantName+"/api/v1/receive",
		withToken(token),
		withRunParameters(&runParams{period: "5000ms", threshold: "1", latency: "10s", duration: "0"}),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(up))

	testutil.Ok(t, e2einteractive.OpenInBrowser("http://"+readExtEndpoint))

	fmt.Printf("\n")
	fmt.Printf("You're all set up!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Observatorium API on host machine: 		%s \n", api.Endpoint("https"))
	fmt.Printf("Observatorium internal server on host machine: 	%s \n", api.Endpoint("http-internal"))
	fmt.Printf("Thanos Query on host machine: 			%s \n", readExtEndpoint)
	fmt.Printf("Loki on host machine: 				%s \n", logsExtEndpoint)
	fmt.Printf("API Token: 					%s \n\n", token)

	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
}
