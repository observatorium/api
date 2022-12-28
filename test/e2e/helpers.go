//go:build integration || interactive

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	"github.com/observatorium/api/test/testtls"
)

// Generates certificates and copies static configuration to the shared directory.
func prepareConfigsAndCerts(t *testing.T, tt testType, e e2e.Environment) {
	testutil.Ok(
		t,
		testtls.GenerateCerts(
			filepath.Join(e.SharedDir(), certsSharedDir),
			getContainerName(t, tt, "observatorium-api"),
			[]string{getContainerName(t, tt, "observatorium-api"), "127.0.0.1"},
			getContainerName(t, tt, "dex"),
			[]string{getContainerName(t, tt, "dex"), "127.0.0.1"},
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
		return "", fmt.Errorf("cannot create new request: %v\n", err)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
		},
	}

	res, err := c.Do(r)
	if err != nil {
		return "", fmt.Errorf("request failed: %v\n", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("cannot read body: %v\n", err)
	}

	var t token
	if err := json.Unmarshal(body, &t); err != nil {
		return "", fmt.Errorf("cannot unmarshal token : %v\n", err)
	}

	return t.IDToken, nil
}

func getContainerName(t *testing.T, tt testType, serviceName string) string {
	switch tt {
	case logs:
		return envLogsName + "-" + serviceName
	case metrics:
		return envMetricsName + "-" + serviceName
	case rules:
		return envRulesAPIName + "-" + serviceName
	case tenants:
		return envTenantsName + "-" + serviceName
	case interactive:
		return envInteractive + "-" + serviceName
	case traces:
		return envTracesName + "-" + serviceName
	case tracesTemplate:
		return envTracesTemplateName + "-" + serviceName
	default:
		t.Fatal("invalid test type provided")
		return ""
	}
}

func getTLSClientConfig(t *testing.T, e e2e.Environment) *tls.Config {
	cert, err := os.ReadFile(filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem"))
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

type tokenRoundTripper struct {
	rt    http.RoundTripper
	token string
}

func (rt *tokenRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Add("Authorization", "bearer "+rt.token)
	return rt.rt.RoundTrip(r)
}
