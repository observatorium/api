package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/pkg/errors"
	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

func TestMetricsReadAndWrite(t *testing.T) {
	e, err := e2e.NewDockerEnvironment("e2e_observatorium_api")
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	certsContainerDir, err := copyTestDir(e.SharedDir(), "../../tmp/certs", "certs")
	testutil.Ok(t, err)

	configsContainerDir, err := copyTestDir(e.SharedDir(), "../config", "config")
	testutil.Ok(t, err)

	readEndpoint, writeEndpoint, extReadEndpoint, _, _, rateLimiter, token := startAndWaitOnBaseServices(t, e, configsContainerDir, certsContainerDir)

	api, err := newObservatoriumAPIService(
		e, "observatorium-api", "", "", "", readEndpoint, writeEndpoint,
		filepath.Join(configsContainerDir, "rbac.yaml"), filepath.Join(configsContainerDir, "tenants.yaml"),
		certsContainerDir, rateLimiter,
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	t.Run("metrics-read-write", func(t *testing.T) {
		up, err := newUpService(
			e, "observatorium-up", "metrics",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/query",
			"https://"+api.InternalEndpoint("https")+"/api/metrics/v1/test-oidc/api/v1/receive",
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

		// Query Thanos to ensure we have correct metrics and labels.
		a, err := promapi.NewClient(promapi.Config{Address: "http://" + extReadEndpoint})
		testutil.Ok(t, err)

		// Assert we have correct metrics and labels in Thanos.
		{
			now := model.Now()
			v, w, err := v1.NewAPI(a).Query(context.Background(), "observatorium_write{}", now.Time())

			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			// TODO: Replace with byte index?
			vs := strings.Split(v.String(), " => ")
			testutil.Equals(
				t,
				"observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\"1610b0c3-c509-4592-a256-a1871353dbfa\"}",
				vs[0],
			)

			// Check timestamp.
			ts := strings.Split(vs[1], " @")
			testutil.Equals(t, fmt.Sprintf("[%v]", now), ts[1])
		}

		// Assert we have recorded all sent values in the 10m range.
		{
			now := model.Now()
			v, w, err := v1.NewAPI(a).Query(context.Background(), "observatorium_write{}[10m]", now.Time())

			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			// Split on every value and ignore first line with metric / labels.
			vs := strings.Split(v.String(), "\n")[1:]
			testutil.Equals(t, 20, len(vs))
		}
	})

	t.Run("metrics-tenant-isolation", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		r, err := http.NewRequest(
			http.MethodGet,
			"https://"+api.Endpoint("https")+"/api/metrics/v1/test-attacker/api/v1/query?query=observatorium_write",
			nil,
		)
		testutil.Ok(t, err)
		r.Header.Add("Authorization", "bearer "+token)

		c := &http.Client{
			Transport: tr,
		}

		res, err := c.Do(r)
		testutil.Ok(t, err)
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		testutil.Ok(t, err)

		msg := "No StoreAPIs matched for this query"
		testutil.Assert(
			t,
			strings.Contains(string(body), msg),
			fmt.Sprintf("failed to assert that the response contains '%s'", msg),
		)
	})

	// TODO: Add rate limiting tests?
}

// Starts and waits until all base services required for metrics test are ready.
func startAndWaitOnBaseServices(
	t *testing.T,
	e e2e.Environment,
	configsContainerDir string,
	certsContainerDir string,
) (metricsReadEndpoint string,
	metricsWriteEndpoint string,
	metricsExtReadEndpoint string,
	logsEndpoint string,
	logsExtEndpoint string,
	rateLimiter string,
	token string,
) {
	dex := newDexService(e, "observatorium-dex", filepath.Join(configsContainerDir, "dex.yaml"))
	gubernator := newGubernatorService(e, "observatorium-gubernator")
	thanosReceive := newThanosReceiveService(
		e, "observatorium-thanos-receive",
		"receive_replica=\"0\"",
		"1610b0c3-c509-4592-a256-a1871353dbfa",
		filepath.Join(configsContainerDir, "hashrings.json"),
	)
	thanosQuery := newThanosQueryService(
		e, "observatorium-thanos-query",
		thanosReceive.InternalEndpoint("grpc"),
	)
	loki := newLokiService(e, "observatorium-loki", filepath.Join(configsContainerDir, "loki.yml"))
	opa := newOPAService(e, "observatorium-opa", configsContainerDir)

	testutil.Ok(t, e2e.StartAndWaitReady(
		dex, gubernator, thanosReceive, thanosQuery, loki, opa,
	))

	createTenantsYAML(
		t,
		filepath.Join(e.SharedDir(), "config"),
		configsContainerDir,
		dex.InternalEndpoint("https"),
		certsContainerDir,
		opa.InternalEndpoint("http"),
	)

	token, err := obtainToken(dex.Endpoint("https"), filepath.Join(e.SharedDir(), "certs"))
	testutil.Ok(t, err)

	return thanosQuery.InternalEndpoint("http"),
		thanosReceive.InternalEndpoint("remote_write"),
		thanosQuery.Endpoint("http"),
		loki.InternalEndpoint("http"),
		loki.Endpoint("http"),
		gubernator.InternalEndpoint("grpc"),
		token
}

// copyTestDir copies a directory from host to the shared directory, returning
// path to where the directory is available within a container.
func copyTestDir(sharedDir string, srcDir string, dirName string) (string, error) {
	if err := exec.Command("cp", "-r", srcDir, sharedDir).Run(); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("copying dir %s", srcDir))
	}

	return filepath.Join(dockerLocalSharedDir, dirName), nil
}

func obtainToken(endpoint string, certPath string) (string, error) {
	type token struct {
		IDToken string `json:"id_token"`
	}

	cert, err := ioutil.ReadFile(filepath.Join(certPath, "ca.pem"))
	if err != nil {
		return "", errors.Wrap(err, "cannot read cert file")
	}

	// TODO: Fix certs?
	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(cert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	data := url.Values{}
	data.Add("grant_type", "password")
	data.Add("username", "admin@example.com")
	data.Add("password", "password")
	data.Add("client_id", "test")
	data.Add("client_secret", "ZXhhbXBsZS1hcHAtc2VjcmV0")
	data.Add("scope", "openid email")

	r, err := http.NewRequest(http.MethodPost, "https://"+endpoint+"/dex/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "cannot create new request")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{
		Transport: tr,
	}

	res, err := c.Do(r)
	if err != nil {
		return "", errors.Wrap(err, "request failed")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	var t token
	if err := json.Unmarshal(body, &t); err != nil {
		return "", errors.Wrap(err, "cannot unmarshal token")
	}

	return t.IDToken, nil
}
