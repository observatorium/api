//go:build integration

package e2e

import (
	"io"
	"net/http"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	"github.com/ghodss/yaml"
)

func TestOpenAPIEndpoint(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(envMetricsName))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, metrics, e)
	_, _, _ = startBaseServices(t, e, metrics)
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("get OpenAPI", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "https://"+api.Endpoint("https")+"/openapi.yaml", nil)
		testutil.Ok(t, err)

		c := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
		}
		resp, err := c.Do(r)
		testutil.Ok(t, err)

		yamlSpec, err := io.ReadAll(resp.Body)
		testutil.Ok(t, err)

		var spec map[string]interface{}
		err = yaml.Unmarshal(yamlSpec, &spec)
		testutil.Ok(t, err)
		_, found := spec["openapi"]
		testutil.Assert(t, found)

		defer resp.Body.Close()
	})
}
