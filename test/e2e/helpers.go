//go:build integration || interactive

package e2e

import (
	"crypto/sha256"
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

// uniqueE2ENetworkName returns a Docker-valid e2e network name (≤16 chars, [-a-zA-Z0-9])
// that is distinct for each Go test. efficientgo/e2e's default name hashes runtime.Caller(3),
// which resolves to testing.tRunner for every test, so bare e2e.New() would assign the same
// network to all parallel tests and reproduce Docker network races.
func uniqueE2ENetworkName(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	return fmt.Sprintf("%x", sum[:8]) // 16 hex digits
}

// Generates certificates and copies static configuration to the shared directory.
func prepareConfigsAndCerts(t *testing.T, e e2e.Environment) {
	testutil.Ok(
		t,
		testtls.GenerateCerts(
			filepath.Join(e.SharedDir(), certsSharedDir),
			getContainerName(e, "observatorium-api"),
			[]string{getContainerName(e, "observatorium-api"), "127.0.0.1"},
			getContainerName(e, "dex"),
			[]string{getContainerName(e, "dex"), "127.0.0.1"},
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

// getContainerName returns the Docker DNS hostname for a service in this environment.
// It must match e2e's naming ({networkName}-{runnableName}) so TLS SANs and OIDC redirects stay correct.
func getContainerName(e e2e.Environment, serviceName string) string {
	return e.Name() + "-" + serviceName
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
	t.Helper()
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
