package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/observatorium/api/test/testtls"
	"github.com/pkg/errors"
)

type testType string

const (
	metrics testType = "metrics"
	logs    testType = "logs"

	dockerLocalSharedDir = "/shared"
	certsSharedDir       = "certs"
	configSharedDir      = "config"

	certsContainerPath   = dockerLocalSharedDir + "/" + certsSharedDir
	configsContainerPath = dockerLocalSharedDir + "/" + configSharedDir

	envMetricsName = "e2e_metrics_read_write"
	envLogsName    = "e2e_logs_read_write_tail"

	defaultTenantID = "1610b0c3-c509-4592-a256-a1871353dbfa"
	mtlsTenantID    = "845cdfd9-f936-443c-979c-2ee7dc91f646"
)

// Generates certificates and copies static configuration to the shared directory.
func prepareConfigsAndCerts(t *testing.T, testType testType, e e2e.Environment) {
	testutil.Ok(
		t,
		testtls.GenerateCerts(
			filepath.Join(e.SharedDir(), certsSharedDir),
			getContainerName(testType, "observatorium_api"),
			[]string{getContainerName(testType, "observatorium_api"), "127.0.0.1"},
			getContainerName(testType, "dex"),
			[]string{getContainerName(testType, "dex"), "127.0.0.1"},
		),
	)

	testutil.Ok(t, exec.Command("cp", "-r", "../config", filepath.Join(e.SharedDir(), configSharedDir)).Run())
}

// obtainToken obtains a bearer token needed for communication with the API.
func obtainToken(endpoint string, tlsConf *tls.Config) (string, error) {
	type token struct {
		IDToken string `json:"id_token"`
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
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
		},
	}

	res, err := c.Do(r)
	if err != nil {
		return "", errors.Wrap(err, "request failed")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "cannot read body")
	}

	var t token
	if err := json.Unmarshal(body, &t); err != nil {
		return "", errors.Wrap(err, "cannot unmarshal token")
	}

	return t.IDToken, nil
}

func getContainerName(testType testType, serviceName string) string {
	if testType == metrics {
		return envMetricsName + "-" + serviceName
	}

	return envLogsName + "-" + serviceName
}

func getTLSClientConfig(t *testing.T, e e2e.Environment) *tls.Config {
	cert, err := ioutil.ReadFile(filepath.Join(filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem")))
	testutil.Ok(t, err)

	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(cert)

	return &tls.Config{
		RootCAs: cp,
	}
}

func assertResponse(t *testing.T, response string, expected string) {
	testutil.Assert(
		t,
		strings.Contains(response, expected),
		fmt.Sprintf("failed to assert that the response '%s' contains '%s'", response, expected),
	)
}
